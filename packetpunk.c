/** @file simple_client.c
 *
 * @brief This simple client demonstrates the basic features of JACK
 * as they would be used by many applications.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <jack/jack.h>
#include <jack/ringbuffer.h>
#include <pcap.h>

jack_port_t *output_port;
jack_client_t *client;
jack_ringbuffer_t *rb;

/* Default snaplen */
const int SNAPLEN = 68;
const int RINGSIZE = 256;
const int PROMISC = 1;

/**
 * The process callback for this JACK application is called in a
 * special realtime thread once for each audio cycle.
 */
int
process (jack_nframes_t nframes, void *arg)
{
	jack_default_audio_sample_t *out;
  size_t  s,r;
  
  /* copy the stuff from the ringbuffer into the output stream */
	out = jack_port_get_buffer (output_port, nframes);
  s = sizeof (jack_default_audio_sample_t) * nframes;
  r = jack_ringbuffer_read (rb, (char*)out, s);

  /* fill with zeros if there is not enough data available */
  if (s>r)
    memset (&out[r], 0, s-r);
	
  return 0;      
}

/**
 * JACK calls this shutdown_callback if the server ever shuts down or
 * decides to disconnect the client.
 */
void
jack_shutdown (void *arg)
{
	exit (1);
}

void
usage (char* name, int code)
{
  char* dc=strrchr(name, '/');
  if(!dc)
    dc=name;
  else
    dc++;

  printf(
    "Usage: %s [OPTION]... [expression]\n\n"
    "   -c name     Jack client name (default: %s)\n"
    "   -n name     Jack server name (default: set by server)\n"
    "   -s snaplen  Capture at most this many bytes of a packet (default: %d)\n"
    "   -p          Do not capture in promiscious mode\n"
    "   -i ifname   Live capture from the specified network interface\n"
    "   -r file     Read from a dump-file\n"
    "   -b frames   Size of ringbuffer in frames (default: %d)\n"
    "\n"
    "You may supply a bpf-expression for packet filtering. See tcpdump manpage for\n"
    "further information.\n",
    name, dc, SNAPLEN, RINGSIZE
  );
  exit(code);
}

int
main (int argc, char *argv[])
{
	const char *client_name;
	const char *server_name = NULL;
	jack_options_t options = JackNullOption;
	jack_status_t status;
  pcap_t* pcap;
  char* iface=NULL;
  char* fname=NULL;
  int   slen=SNAPLEN;
  int   rs=RINGSIZE;
  char  errbuf[PCAP_ERRBUF_SIZE];
  int   promisc=PROMISC;

  client_name = strrchr(argv[0], '/');
  if(!client_name)
    client_name=argv[0];
  else
    client_name++;

  int opt;
  while ((opt = getopt(argc, argv, "c:n:s:pi:r:b:")) != -1) {
    switch (opt) {
    case 'c':
        client_name=optarg;
        break;
    case 'n':
        server_name=optarg;
        options |= JackServerName;
        break;
    case 's':
        slen=atoi(optarg);
        break;
    case 'p':
        promisc=0;
        break;
    case 'i':
        iface=optarg;
        break;
    case 'r':
        fname=optarg;
        break;
    case 'b':
        rs=atoi(optarg);
        break;
    case '?':
        usage(argv[0],0);
        break;
    default: /* '?' */
        printf("Invalid option %c\n",opt);
        usage(argv[0],EXIT_FAILURE);
    }
  }

  /* open the pcap source */
  if ((iface && fname) || (!iface && !fname)) {
    printf("Please specify either a interface or a dump file as packet source\n");
    usage(argv[0],EXIT_FAILURE);
  }

  if (iface) {
    pcap = pcap_open_live(iface, slen, promisc, 0, errbuf);
    if (!pcap) {
      printf("Failed to open pcap source %s: %s\n", iface, errbuf);
      exit(EXIT_FAILURE);
    }
  }

  if (fname) {
    pcap = pcap_open_offline(fname, errbuf);
    if (!pcap) {
      printf("Failed to open dump file %s: %s\n", iface, errbuf);
      exit(EXIT_FAILURE);
    }
  }

  /* set bpf filter */
  if (optind < argc) {
    int   i,s;
    char* bpf_str;
    struct bpf_program bpf_prog;

    for (s=0, i=optind; i<argc; i++) {
      s += strlen(argv[i]) + 1;
    }

    bpf_str = malloc(s);
    if (!bpf_str) {
      printf("Failed to malloc space for bpf filter\n");
      exit(EXIT_FAILURE);
    }

    bpf_str[0]=0;
    for (i=optind; i<argc; i++) {
      strcat(bpf_str,argv[i]);
      strcat(bpf_str," ");
    }

    printf("Setting bpf filter to %s\n", bpf_str);

    if (0>pcap_compile(pcap, &bpf_prog, bpf_str, 1, 0)) {
      printf("Failed to compile bpf filter\n");
      exit(EXIT_FAILURE);
    }

    if (0>pcap_setfilter(pcap, &bpf_prog)) {
      printf("Failed to set bpf filter\n");
      exit(EXIT_FAILURE);
    }

    pcap_freecode(&bpf_prog);
    free(bpf_str);
  }

  /* allocate ringbuffer */
  rb=jack_ringbuffer_create (rs*sizeof(jack_default_audio_sample_t));
  if (!rb) {
    printf("Failed to allocate ringbuffer\n");
    exit(EXIT_FAILURE);
  }

	/* open a client connection to the JACK server */
	client = jack_client_open (client_name, options, &status, server_name);
	if (client == NULL) {
		fprintf (stderr, "jack_client_open() failed, "
			 "status = 0x%2.0x\n", status);
		if (status & JackServerFailed) {
			fprintf (stderr, "Unable to connect to JACK server\n");
		}
		exit (1);
	}
	if (status & JackServerStarted) {
		fprintf (stderr, "JACK server started\n");
	}
	if (status & JackNameNotUnique) {
		client_name = jack_get_client_name(client);
		fprintf (stderr, "unique name `%s' assigned\n", client_name);
	}

	/* tell the JACK server to call `process()' whenever
	   there is work to be done.
	*/

	jack_set_process_callback (client, process, 0);

	/* tell the JACK server to call `jack_shutdown()' if
	   it ever shuts down, either entirely, or if it
	   just decides to stop calling us.
	*/

	jack_on_shutdown (client, jack_shutdown, 0);

	/* display the current sample rate. 
	 */

	printf ("engine sample rate: %" PRIu32 "\n",
		jack_get_sample_rate (client));

	/* create two ports */

	output_port = jack_port_register (client, "output",
					  JACK_DEFAULT_AUDIO_TYPE,
					  JackPortIsOutput, 0);

	/* Tell the JACK server that we are ready to roll.  Our
	 * process() callback will start running now. */

	if (jack_activate (client)) {
		fprintf (stderr, "cannot activate client");
		exit (1);
	}

	/* read packets from pcap source and write it into the ringbuffer */
  char    *buf;
  struct  pcap_pkthdr *h;
  size_t  s;
  u_int   pcnt=0;

	while (0 <= pcap_next_ex(pcap, &h, (const u_char**) &buf)) {
    if (!buf) break;

    pcnt++;

    s = jack_ringbuffer_write_space(rb);
    if (s==0) continue;
    
    if (s>h->caplen) s=h->caplen;
    jack_ringbuffer_write(rb,buf,s);
	}

	jack_client_close (client);
  
  struct  pcap_stat  ps;
  if(!pcap_stats(pcap, &ps)) {
    printf(
      "%d packets captured\n"
      "%d received by filter\n"
      "%d packets dropped by kernel\n",
      ps.ps_recv, pcnt, ps.ps_drop
    );
  }
  else {
    pcap_perror(pcap,"Failed to optain packet statistics");
  }
	exit (0);
}
