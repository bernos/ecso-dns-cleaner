package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
)

var (
	region         = flag.String("region", "ap-southeast-2", "AWS region")
	zone           = flag.String("zone", "", "DNS zone id")
	records        = flag.String("records", "", "Pattern to match records to clean")
	ec2HostPattern = regexp.MustCompile("^ip-([0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3})..*")
)

func main() {
	flag.Parse()

	p := strings.Replace(*records, ".", "\\.", -1)
	p = strings.Replace(p, "*", ".*", -1)
	pattern := regexp.MustCompile("^" + p + "$")

	sess := session.Must(session.NewSession(&aws.Config{
		Region: region,
	}))

	r53 := route53.New(sess)
	ec2API := ec2.New(sess)

	for {
		start := time.Now()
		log.Printf("==== Running DNS cleanup")
		err := cleanUp(r53, ec2API, pattern)

		if err != nil {
			log.Printf("ERROR: %s", err.Error())
		}
		log.Printf("==== Cleanup completed in %s", time.Since(start))
		time.Sleep(time.Second * 30)
	}
}

func cleanUp(r53API route53iface.Route53API, ec2API ec2iface.EC2API, pattern *regexp.Regexp) error {
	zone, err := FindHostedZone(r53API, *zone)

	if err != nil {
		return err
	}

	recordSets, err := FetchRecordSets(r53API, *zone.Id, "SRV", pattern)

	if err != nil {
		return err
	}

	instances, err := FetchInstances(ec2API)

	if err != nil {
		return err
	}

	changes := make([]*route53.Change, 0)

	for _, rs := range recordSets {
		log.Printf("Processing record set %s\n", *rs.Name)

		var instance *ec2.Instance

		for _, r := range rs.ResourceRecords {
			srv, err := ParseSRVRecord(*r.Value)

			// Log and continue on error here. One record failing
			// to parse is not critical
			if err != nil {
				log.Printf("ERROR: %s", err.Error())
				continue
			}

			log.Printf("Finding instance with private DNS name %s", srv.Target)

			for _, i := range instances {
				if *i.PrivateDnsName == srv.Target {
					instance = i
					break
				}
			}

			if instance != nil {
				break
			}
		}

		if instance != nil {
			log.Printf("Found ec2 instance: %s", *instance.PrivateDnsName)
			log.Printf("Instance state: %s", *instance.State.Name)
		} else {
			log.Printf("No instances found")
		}

		if instance == nil || *instance.State.Name != "running" {
			log.Printf("I WILL KILL THIS RECORD SET")
			changes = append(changes, &route53.Change{
				Action:            aws.String("DELETE"),
				ResourceRecordSet: rs,
			})
		}
	}

	if len(changes) > 0 {
		log.Printf("Deleting %d record sets", len(changes))

		_, err := r53API.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
			HostedZoneId: zone.Id,
			ChangeBatch: &route53.ChangeBatch{
				Comment: aws.String("Deleted by ecso-dns-cleaner"),
				Changes: changes,
			},
		})

		if err != nil {
			return err
		}

		log.Printf("Done")
	} else {
		log.Printf("Nothing to delete")
	}

	return nil
}

func FindHostedZone(svc route53iface.Route53API, name string) (*route53.HostedZone, error) {
	log.Printf("Finding hosted zone %s...", name)

	resp, err := svc.ListHostedZonesByName(&route53.ListHostedZonesByNameInput{
		DNSName: aws.String(name),
	})

	if err != nil {
		return nil, err
	}

	if len(resp.HostedZones) == 0 {
		return nil, fmt.Errorf("Found no hosted zone named %s", name)
	}

	if len(resp.HostedZones) > 1 {
		return nil, fmt.Errorf("Found more than one hosted zone with name %s", name)
	}

	return resp.HostedZones[0], nil
}

// FetchInstances fetches all ec2 instances
func FetchInstances(svc ec2iface.EC2API) ([]*ec2.Instance, error) {
	log.Printf("Fetching instances...")

	instances := make([]*ec2.Instance, 0)
	input := &ec2.DescribeInstancesInput{}

	err := svc.DescribeInstancesPages(input, func(resp *ec2.DescribeInstancesOutput, last bool) bool {
		for _, r := range resp.Reservations {
			for _, i := range r.Instances {
				instances = append(instances, i)
			}
		}
		return !last
	})

	return instances, err
}

// FetchRecordSets fetches all record sets in a zone matching the type provided
// as rsType, and the name provided by the name regexp
func FetchRecordSets(svc route53iface.Route53API, zoneID string, rsType string, name *regexp.Regexp) ([]*route53.ResourceRecordSet, error) {
	log.Printf("Fetching %s recordsets matching %s", rsType, name)

	output := make([]*route53.ResourceRecordSet, 0)

	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	}

	err := svc.ListResourceRecordSetsPages(input, func(r *route53.ListResourceRecordSetsOutput, last bool) bool {
		output = append(output, FilterRecordSets(r.ResourceRecordSets, "SRV", name)...)
		return !last
	})

	if err != nil {
		return output, err
	}

	return output, nil
}

// FilterRecordSets filters out ResourceRecordSets whose type or name do not
// match the rsType of nameRegexp
func FilterRecordSets(rs []*route53.ResourceRecordSet, rsType string, nameRegexp *regexp.Regexp) []*route53.ResourceRecordSet {
	output := make([]*route53.ResourceRecordSet, 0)

	for _, record := range rs {
		if *record.Type == rsType && nameRegexp.MatchString(*record.Name) {
			output = append(output, record)
		}
	}

	return output
}

func HandleSRVRecordSet(r *route53.ResourceRecordSet) {
	log.Printf("Handling %s\n", *r.Name)

	for _, rec := range ParseSRVRecordSet(r) {
		ip, err := ResolveHostName(rec.Target)

		if err != nil {
			log.Printf("ERROR: %s", err)
		} else {
			log.Printf("Host: %s, IP: %s", rec.Target, ip)

			up := IsHostUp(fmt.Sprintf("%s:%d", ip, rec.Port))

			if !up {
				log.Printf("HOST IS DOWN")
			} else {
				log.Printf("HOST IS UP")
			}
		}
	}
}

// ParseSRVRecordSet parses all records from a ResourceRecordSet into a slice
// of *net.SRV. If any records fail to parse erros will be logged
func ParseSRVRecordSet(r *route53.ResourceRecordSet) []*net.SRV {
	addrs := make([]*net.SRV, 0)

	for _, rec := range r.ResourceRecords {
		srv, err := ParseSRVRecord(*rec.Value)

		if err != nil {
			log.Printf("ERROR: %s", err.Error())
		} else if srv != nil {
			addrs = append(addrs, srv)
		}
	}

	return addrs
}

// ParseSRVRecord parses an SRV dns record in the
// format priority weight port target into a *net.SRV
func ParseSRVRecord(r string) (*net.SRV, error) {
	fields := strings.Split(r, " ")

	if len(fields) != 4 {
		return nil, fmt.Errorf("Not a valid SRV record")
	}

	priority, priorityErr := strconv.Atoi(fields[0])
	weight, weightErr := strconv.Atoi(fields[1])
	port, portErr := strconv.Atoi(fields[2])

	if priorityErr != nil || weightErr != nil || portErr != nil {
		return nil, fmt.Errorf("Failed to parse SRV record")
	}

	return &net.SRV{
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Port:     uint16(port),
		Target:   fields[3],
	}, nil
}

// ResolveHostName takes an ec2 private hostname and resolves it to an ip address
// based on the naming convention ip-xxx-xxx-xxx-xxx.some.domain
func ResolveHostName(host string) (string, error) {
	matches := ec2HostPattern.FindStringSubmatch(host)

	if len(matches) != 2 {
		return "", fmt.Errorf("Failed to resolve hostname %s", host)
	}

	return strings.Replace(matches[1], "-", ".", -1), nil
}

// IsHostUp attempts to establish a TCP connection to the given address. If the
// attempt is successful CheckHost will return true
func IsHostUp(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)

	if err != nil {
		log.Printf("ERROR: %s", err.Error())
		return false
	}

	conn.Close()

	return true
}
