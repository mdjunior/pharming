# pharming
Simple tool for monitoring DNS Hijacking


Installing
----------

To install the dependencies, run:

    cpanm --installdeps .


Use
---

Create config...

	./pharming.pl --create


Add server to monitorng...

	./pharming.pl --server-add 8.8.8.8 --description "Google Public DNS"


Remove server to monitorng...

	./pharming.pl --server-remove 8.8.8.8


Add domain to monitoring...

	./pharming.pl --domain-add www.example.com --description "Example Domain"


Remove domain to monitoring...

	./pharming.pl --domain-remove www.example.com


Add mail to alert...

	./pharming.pl --mail-add john@example.com --description "John Smith"


Remove mail to alert...

	./pharming.pl --mail-remove john@example.com


Show all...

	./pharming.pl --show-all
	$VAR1 = {
	          'alerts' => [
	                        {
	                          'mail' => 'john@example.com',
	                          'description' => 'John Smith'
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


Run...

	./pharming.pl --run
	run-check manoel.junior Manoels-MacBook-Pro 8.8.8.8 example.com 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 8.8.4.4 example.com 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.222.222 example.org 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.222.222 example.com 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.222.222 example.net 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.220.220 example.org 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.220.220 example.com 93.184.216.34 ok
	run-check manoel.junior Manoels-MacBook-Pro 208.67.220.220 example.net 93.184.216.34 ok



