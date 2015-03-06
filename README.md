# pharming
Simple tool for monitoring DNS Hijacking


Installing
----------

To install the dependencies, run:

    cpanm --installdeps .

or (old way)

	cpan install Authen::SASL Net::SSLeay Net::SMTP::SSL Readonly

Help
----

	./pharming.pl --help
        pharming
            Simple tool for monitoring DNS Hijacking

        --help
            Show this help

        --create
            Create a database

        --show-all
            Show all information

        --server-add
            Add DNS server to monitoring (optional: --description "DNS description")

        --server-remove
            Remove DNS server to monitoring

        --domain-add
            Add domain to monitoring (optional: --description "Example home page")

        --domain-remove
            Remove domain to monitoring

        --mail-add
            Add mail to send alerts
            REQUIRED:   --notify nok or --notify ok
                        --smtp smtp.example.com
                        --auth 'john@example.com:pass' (ex: user:pass)

        --mail-remove john@example.com
            Remove mail from alerts

        --run
            Run! (useful for crontab) (optional: --verbose)


Use
---

Create config...

	./pharming.pl --create


Add server to monitoring...

	./pharming.pl --server-add 8.8.8.8 --description "Google Public DNS"


Remove server to monitorng...

	./pharming.pl --server-remove 8.8.8.8


Add domain to monitoring...

	./pharming.pl --domain-add www.example.com --description "Example Domain"


Remove domain to monitoring...

	./pharming.pl --domain-remove www.example.com


Add mail to send alerts...

	./pharming.pl --mail-add john@example.com --notify nok --smtp smtp.example.com --auth 'john@example.com:pass' --description "John Smith"

In this case, John will be notified where the scan result in `nok`. Possible values are: `ok` or `nok.


Remove mail to alert...

	./pharming.pl --mail-remove john@example.com


Show all...

	./pharming.pl --show-all
	$VAR1 = {
	          'mails' => [
	                        {
	                          'mail' => 'john@example.com',
	                          'description' => 'John Smith',
	                          'notify' => 'nok',
	                          'smtp_server' => 'smtp.example.com',
	                          'auth' => 'john@example.com:pass'
	                        }
	                      ],
	          'servers' => [
	                         {
	                           'server' => '8.8.8.8',
	                           'ptr' => 'google-public-dns-a.google.com.',
	                           'description' => 'Google Public DNS'
	                         },
	                         {
	                           'ptr' => 'google-public-dns-b.google.com.',
	                           'description' => 'Google Public DNS',
	                           'server' => '8.8.4.4'
	                         },
	                         {
	                           'server' => '208.67.222.222',
	                           'description' => 'OpenDNS',
	                           'ptr' => 'resolver1.opendns.com.'
	                         },
	                         {
	                           'server' => '208.67.220.220',
	                           'ptr' => 'resolver2.opendns.com.',
	                           'description' => 'OpenDNS'
	                         }
	                       ],
	          'is_running' => 0,
	          'domains' => [
	                         {
	                           'description' => 'Example Domain',
	                           'domain' => 'example.org'
	                         },
	                         {
	                           'description' => 'Example Domain',
	                           'domain' => 'example.com'
	                         },
	                         {
	                           'domain' => 'example.net',
	                           'description' => 'Example Domain'
	                         }
	                       ]
	        };


Run... (verbose)

	./pharming.pl --run -v
	run-check manoel.junior Manoels-MacBook-Pro 8.8.8.8 example.com 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 8.8.4.4 example.com 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.222.222 example.org 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.222.222 example.com 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.222.222 example.net 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.220.220 example.org 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.220.220 example.com 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.220.220 example.net 93.184.216.34 ok


Mail template
-------------

	From: john@example.com
	To: john@example.com
	Subject: [PHARMING] Report for nok domains at Fri Mar  6 02:20:17 2015

	-> example.net
		SERVER: 208.67.220.220
		EXPECTED: 93.184.216.34
		RESULT: 93.184.216.35
		DETAILS: $VAR1 = {
	          'ttl' => 53343,
	          'ad' => 0,
	          'ra' => 1,
	          'rdstring' => '93.184.216.35',
	          'owner' => 'example.net',
	          'time' => 'Fri Mar  6 02:20:16 2015',
	          'rcode' => 'NOERROR',
	          'id' => 17840,
	          'cd' => 0,
	          'aa' => 0,
	          'tc' => 0,
	          'qr' => 1,
	          'type' => 'A',
	          'opcode' => 'QUERY',
	          'class' => 'IN',
	          'z' => 0,
	          'rd' => 0
	        };

	LOG
	action:run-check-config user:manoel.junior host:manoels-mbp info:1 result:ok
	action:get_authoritative_nameservers user:manoel.junior host:manoels-mbp info:example.net result:b.iana-servers.net a.iana-servers.net
	action:get_authoritative_record user:manoel.junior host:manoels-mbp info:example.net result:93.184.216.34
	action:get_authoritative_nameservers user:manoel.junior host:manoels-mbp info:example.com result:a.iana-servers.net b.iana-servers.net
	action:get_authoritative_record user:manoel.junior host:manoels-mbp info:example.com result:93.184.216.34
	action:get_authoritative_nameservers user:manoel.junior host:manoels-mbp info:example.org result:b.iana-servers.net a.iana-servers.net
	action:get_authoritative_record user:manoel.junior host:manoels-mbp info:example.org result:93.184.216.34
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.net result:208.67.220.220->93.184.216.35
	action:run-check-domain user:manoel.junior host:manoels-mbp server:208.67.220.220 domain:example.net addr:93.184.216.35 result:nok
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.com result:208.67.220.220->93.184.216.34
	action:run-check-domain user:manoel.junior host:manoels-mbp server:208.67.220.220 domain:example.com addr:93.184.216.34 result:ok
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.org result:208.67.220.220->93.184.216.34
	action:run-check-domain user:manoel.junior host:manoels-mbp server:208.67.220.220 domain:example.org addr:93.184.216.34 result:ok
	action:run-check-nameserver user:manoel.junior host:manoels-mbp info:208.67.220.220 result:ok
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.net result:208.67.222.222->93.184.216.34
	action:run-check-domain user:manoel.junior host:manoels-mbp server:208.67.222.222 domain:example.net addr:93.184.216.34 result:ok
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.com result:208.67.222.222->93.184.216.34
	action:run-check-domain user:manoel.junior host:manoels-mbp server:208.67.222.222 domain:example.com addr:93.184.216.34 result:ok
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.org result:208.67.222.222->93.184.216.34
	action:run-check-domain user:manoel.junior host:manoels-mbp server:208.67.222.222 domain:example.org addr:93.184.216.34 result:ok
	action:run-check-nameserver user:manoel.junior host:manoels-mbp info:208.67.222.222 result:ok
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.net result:8.8.4.4->
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.com result:8.8.4.4->
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.org result:8.8.4.4->
	action:run-check-nameserver user:manoel.junior host:manoels-mbp info:8.8.4.4 result:ok
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.net result:8.8.8.8->
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.com result:8.8.8.8->93.184.216.34
	action:run-check-domain user:manoel.junior host:manoels-mbp server:8.8.8.8 domain:example.com addr:93.184.216.34 result:ok
	action:get_recursive_record user:manoel.junior host:manoels-mbp info:example.org result:8.8.8.8->
	action:run-check-nameserver user:manoel.junior host:manoels-mbp info:8.8.8.8 result:ok
