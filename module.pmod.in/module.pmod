//! a module for decoding syslog messages (RFC 3164)
//! because syslog messages are often improperly formatted (per the RFC)
//! we have a number of levels of strictness.

//!
constant __author = "Bill Welliver <bill@welliver.org>";
constant __version = "1.0";

//! syslog port number
constant SYSLOG_PORT=514;

//! kernel messages
constant FACILITY_KERNEL=0;

//! user-level messages
constant FACILITY_USER=1;

//! mail system
constant FACILITY_MAIL=2;

//! system daemons
constant FACILITY_DAEMON=3;

//! security/authorization messages 
constant FACILITY_AUTH=4;

//! messages generated internally by syslogd
constant FACILITY_SYSLOG=5;

//! line printer subsystem
constant FACILITY_LP=6;

//! network news subsystem
constant FACILITY_NEWS=7;

//! UUCP subsystem
constant FACILITY_UUCP=8;

//! clock daemon 
constant FACILITY_CLOCK=9;

//! security/authorization messages 
constant FACILITY_SECURITY=10;

//! FTP daemon
constant FACILITY_FTP=11;

//! NTP subsystem
constant FACILITY_NTP=12;

//! log audit 
constant FACILITY_LOGAUDIT=13;

//! log alert 
constant FACILITY_LOGALERT=14;

//! clock daemon 
constant FACILITY_CLOCK2=15;

//! local use 0  (local0)
constant FACILITY_LOCAL0=16;

//! local use 1  (local1)
constant FACILITY_LOCAL1=17;

//! local use 2  (local2)
constant FACILITY_LOCAL2=18;

//! local use 3  (local3)
constant FACILITY_LOCAL3=19;

//! local use 4  (local4)
constant FACILITY_LOCAL4=20;

//! local use 5  (local5)
constant FACILITY_LOCAL5=21;

//! local use 6  (local6)
constant FACILITY_LOCAL6=22;

//! local use 7  (local7)
constant FACILITY_LOCAL7=23;

//! Emergency: system is unusable
constant SEVERITY_EMERGENCY=0;

//! Alert: action must be taken immediately
constant SEVERITY_ALERT=1;

//! Critical: critical conditions
constant SEVERITY_CRITICAL=2;

//! Error: error conditions
constant SEVERITY_ERROR=3;

//! Warning: warning conditions
constant SEVERITY_WARNING=4;

//! Notice: normal but significant condition
constant SEVERITY_NOTICE=5;

//! Informational: informational messages
constant SEVERITY_INFO=6;

//! Debug: debug-level messages
constant SEVERITY_DEBUG=7;

//! decode a syslog message, as long as it has a proper facility/severity code.
//! 
//! @param packet
//!  a string containing the raw syslog packet
//! @returns
//!  a mapping of decoded data, consisting of the facility, severity and 
//!  message of the balance of the syslog packet (presumably the message)
//!   @mapping
//!   @member int facility
//!
//!   @member int severity
//!
//!   @member string message
//!   @endmapping
mapping sloppy_decode(string packet)
{
  string message;
  int work, facility, severity;

  if(sscanf(packet, "<%d>%s", 
    work, message)!=2)
  error("invalid syslog packet.\n");
  facility=work/8;
  severity=work%8;

  return (["facility": facility, "severity": severity, "message": (message-"\0")]);
}

//! strictly decode a syslog message, requiring all fields
//!
//! @param packet
//!  a string containing the raw syslog packet
//! @returns
//!  a mapping containing the decoded syslog message, or zero if the 
//!  message was not properly formatted.
//!   @mapping
//!   @member int facility
//!
//!   @member int severity
//!
//!   @member string host
//!
//!   @member object timestamp
//!     a @[Calendar.Time] object
//!   @member string message
//!   @endmapping
//!
//! @example
//! > Syslog.decode("<11>Aug  7 17:36:10 localhost joeuser: [ID 702911 user.error] test syslog message");
//! (1) Result: 
//! ([ /* 6 elements */
//!    "facility":1,
//!    "host":"localhost",
//!    "message":"[ID 702911 user.error] test syslog message",
//!    "severity":3,
//!    "timestamp":"Aug  7 17:36:10"
//!  ])
mapping decode(string packet)
{
  int facility;
  int severity;
  string timestamp;
  string host;
  string message;
  string mon,day,time;

  mapping p=sloppy_decode(packet);
  facility=p->facility;
  severity=p->severity;
  packet=p->message;

  if(sscanf(packet, "%3s %2s %s %s %s",
    mon, day, time, host, message)!=5)
    return 0;
  timestamp=mon + " " + day + " " + time;
  return (["facility": facility, "severity": severity, "message": 
    (message-"\0"), "host": host, "timestamp": timestamp]);
}

//!  returns a @[Calendar.Time] object corresponding to the syslog 
//!  timestamp input.
//!
//!  @example
//!  > Syslog.decode_timestamp(Syslog.decode(packet)->timestamp);
//!  (1) Result: Second(Thu 7 Aug 2003 17:30:50 EDT)
//!  
object decode_timestamp(string stamp)
{
  return Calendar.parse("%M%*[ ]%D %h:%m:%s", stamp);
}

//! returns a syslog time string corresponding to the @[Calendar.Time] 
//! object input.
//!
//! @example
//!  > Syslog.encode_timestamp(Calendar.now());
//!  (4) Result: "Aug  7 17:33:19"
string encode_timestamp(object stamp)
{
  return 
    sprintf("%s %' '2d %02d:%02d:%02d", stamp->month_shortname(), 
      stamp->month_day(), stamp->hour_no(), stamp->minute_no(), 
      stamp->second_no());
}

//! encode a syslog message
//!
//! @param data
//!   @mapping
//!   @member int facility
//!
//!   @member int severity
//!
//!   @member string host
//!
//!   @member object timestamp
//!
//!   @member string message
//!   @endmapping
//!
//! @returns
//!  a raw syslog packet suitable for sending to syslogd.
string|int encode(mapping data)
{
  string packet="";
  int work=(data->facility*8 + data->severity);
  packet+="<" + work + ">";
  packet+=encode_timestamp(data->timestamp);
  packet+=" " + data->host + " " + data->tag + data->message;
  if(sizeof(packet)>1024) packet=packet[0..1023];
  return packet;
}

//! send a syslog message
//!
//! @param host
//!   host to send the message to
//! @param facility
//!   facility code
//! @param severity
//!   severity code
//! @param message
//!   the message
//! @param fromhost
//!   an optional hostname or address from which the message should be 
//!   marked as being from. if not specified, the value of 
//!   @[gethostname]() is provided.
//! @param tag
//!   an optional string containing the tag of the sender
//! @param timestamp 
//!   an optional @[Calendar.Time] object representing the time the event occurred
//!   if not specified, the time is assumed to be @[Calendar.now]().
//! @returns
//!   1 on success, 0 otherwise.
//!
int send_message(string host, int facility, int severity, string message, 
  string|void fromhost, string|void tag, object|void timestamp)
{
  if(!host||host=="") host="localhost";
  string packet=encode((["facility": facility, "severity": 
    severity, "timestamp": (timestamp||Calendar.now()),
    "host": (fromhost||gethostname()), "tag": (tag||""),
    "message": message]));
  object UDP=Stdio.UDP();
  UDP->connect(host, SYSLOG_PORT);
  if(!UDP->send(host, SYSLOG_PORT, packet))
    return 0;

  return 1;
}
