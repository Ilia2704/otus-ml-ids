@load base/protocols/dns
@load base/protocols/http

redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1hr;

event zeek_init()
    {
    print "IDS/ML lab: Zeek live capture started";
    }
