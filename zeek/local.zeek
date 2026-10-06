@load base/protocols/dns
@load base/protocols/http

redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1hr;

event zeek_init()
    {
    print "IDS/ML lab: Zeek live capture started";
    # Optional finite lecture capture handshake; unused by the regular live stack.
    if ( getenv("RULE_CAPTURE_READY") != "" )
        {
        local ready = open(getenv("RULE_CAPTURE_READY"));
        print ready, "ready";
        close(ready);
        }
    }
