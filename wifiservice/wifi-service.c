#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <libconfig.h>
#include <time.h>
#include <dirent.h>
#include <curl/curl.h>
#include <pthread.h>
#include <sys/select.h>
#include <pcap.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>


#define DAEMON_NAME "Wifi Service"
#define DEMONIZE

#define  NumberOfRecordsPerFile 119999
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define NumberOfRecords 1000
#define MaxLengthOfAP 31


#define for_each_opt(opt, long, short) while ((opt=getopt_long(argc, argv, short ? short:"+", long, NULL)) != -1)

static volatile int signal_received = 0;
static char quit = 0;

static char cpuid[17];

static int GlobalCount = 0;
static int count = 0;

static FILE *fptr;
static int file_open = 0;
static int global_file_write_count = 0;

pcap_t *handle;			/* Session handle */

struct __attribute__((__packed__))WIFI{
	uint8_t mac[6];
	char AP[MaxLengthOfAP];
	long date_time;
	int8_t rssi;
	struct WIFI * next;

};

typedef struct WIFI WIFIDevice;

static WIFIDevice * firstOnSend;

pthread_mutex_t WIFIDmutex = PTHREAD_MUTEX_INITIALIZER;

static char * WebServiceAddress;
static char * DateFormat;


static void sigint_handler(int sig){
	printf("Received signal \n\r");
	signal_received = SIGTERM;
	quit = 1;
	pcap_breakloop(handle);
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// sending functions ///////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
static int sendData(char * data, char * WebURL, int debug){
	CURL *curl;
	CURLcode res;
 

	struct curl_slist *headerlist = NULL;
	static const char buf[] = "Expect:";
	FILE *f;
	if(debug)
	f = fopen("/dev/null", "wb");

	curl_global_init(CURL_GLOBAL_ALL);
 
  
	curl = curl_easy_init();
 
	headerlist = curl_slist_append(headerlist, buf);
	curl_slist_append(headerlist, "Accept: application/json");
	curl_slist_append(headerlist, "Content-Type: application/json");
	curl_slist_append(headerlist, "charsets: utf-8");

	if(curl) {
		curl_easy_setopt(curl, CURLOPT_POST,1);
		curl_easy_setopt(curl, CURLOPT_URL,WebURL);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT ,300); 
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600); //timeout in seconds
		curl_easy_setopt(curl,CURLOPT_POSTFIELDS,data);

		if(debug)
 		curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);

		res = curl_easy_perform(curl);
		
		if(res != CURLE_OK){
	      		syslog(LOG_ERR, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
			return 2;
		}
		curl_easy_cleanup(curl);

    		curl_slist_free_all(headerlist);
		curl_global_cleanup();
		
		if(debug)
		fclose(f);	
		return 0;
  	}else{
		curl_easy_cleanup(curl);

    		curl_slist_free_all(headerlist);
		curl_global_cleanup();
		if(debug)
		fclose(f);
		return 1;
	}
}

static int sendDataOnGoogle(WIFIDevice * curr){
	CURL *curl;
	CURLcode res;
	char count[10];
	char date_time[25];
	char MAC[20];
	char RSSI[5];

	struct tm *loctime;
 
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	//struct curl_slist *headerlist=NULL;
	//static const char buf[] = "Expect:";
	return 0;
	FILE *f = fopen("/dev/null", "wb");
 
	curl_global_init(CURL_GLOBAL_ALL);

// add time 
	syslog(LOG_NOTICE,"Uping the data ");
	loctime = localtime(&curr->date_time);
	strftime (date_time, 22, "%Y-%m-%d %H:%M:%S", loctime);
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.1118994506",
               CURLFORM_COPYCONTENTS, date_time,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done time");
//add cpu id
//	syslog(LOG_NOTICE,"cpuid %s",cpuid);
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.905449199",
               CURLFORM_COPYCONTENTS, cpuid,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done cpuid");
//MAC of detected
//	syslog(LOG_NOTICE,"cpuid %s",count);
	sprintf(MAC,"%02X:%02X:%02X:%02X:%02X:%02X", curr->mac[0],curr->mac[1],curr->mac[2],curr->mac[3],curr->mac[4],curr->mac[5]);
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.774739743",
               CURLFORM_COPYCONTENTS, MAC,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done count");
// RSSI of the detected MAC
	sprintf(RSSI,"%d",curr->rssi);
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.1358910262",
               CURLFORM_COPYCONTENTS, RSSI,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done scan window");
//AP for this MAC
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.1675396143",
               CURLFORM_COPYCONTENTS, curr->AP,
               CURLFORM_END);
 
	curl = curl_easy_init();
	//headerlist = curl_slist_append(headerlist, buf);

	if(curl) {

	    curl_easy_setopt(curl, CURLOPT_URL, "https://docs.google.com/a/gistic.org/forms/d/1zEa92f1TdRSs_jJ3boPTthkUvdCC_-e41ulAcZDnZrY/formResponse");

	    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);


		curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
//	 syslog(LOG_NOTICE, "gonna perform curl easy perform");
	res = curl_easy_perform(curl);
	    if(res != CURLE_OK){
      		syslog(LOG_ERR, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
			return 2;
		}
 //	 syslog(LOG_NOTICE, "cleanup curl");
	    curl_easy_cleanup(curl);
//  	 syslog(LOG_NOTICE, "freeing up form");
    	curl_formfree(formpost);

		fclose(f);
	syslog(LOG_NOTICE, "upped the data");
	
		return 0;
  	}else{
		syslog(LOG_NOTICE, "upped the data");
		fclose(f);
		return 1;
	}
}

static void * uploadData(){
	char processorTemp[7];
	char ambientTemp[7];
	int i,j,d;
	WIFIDevice * curr;
	WIFIDevice * prevcurr;
	quit = 0;
	char tempData[180]; //Maximum packet length would be 170 but making it 180 for if we increase it
	char data[180*NumberOfRecords + 5];//extra five for brackets and any other 
	while(!quit){
		pthread_mutex_lock(&WIFIDmutex);
		curr = firstOnSend;
		pthread_mutex_unlock(&WIFIDmutex);
		if ( NULL != curr ){
////////////////////////////////////////////////////////////////////////////////////////
			pthread_mutex_lock(&WIFIDmutex);
			i = 0;
			while( curr && i < NumberOfRecords){
				curr = curr->next;
				i++;
			}
			data[0] = '[';
			data[1] = 0;
			curr = firstOnSend;

			for ( j = 0; j < i ; j++ ){
				uint8_t *mac;
				struct tm * loctime;
				char date_time[30];
				loctime=localtime(&curr->date_time);
				strftime (date_time, 29, DateFormat, loctime);
				sprintf(tempData, "{\"storedAccessPointName\":\"%s\",\"RSSI\":\"%d\",\"date\":\"%s\",\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"raspberry_ID\":\"%s\",\"site_ID\":\"-1\"},", curr->AP, curr->rssi,
				date_time,
				curr->mac[0],curr->mac[1],curr->mac[2],curr->mac[3],curr->mac[4],curr->mac[5],cpuid);
				strcat(data,tempData);
				curr = curr->next;
			}
			pthread_mutex_unlock(&WIFIDmutex);
			d = strlen(data);
			data[d-1] = ']';
//			syslog (LOG_NOTICE, "%s",data );
			if ( d > 10 && sendData(data,WebServiceAddress,1) == 0 ){
				
				pthread_mutex_lock(&WIFIDmutex);
				for ( j = 0 ; j < i; j++ ){
					curr = firstOnSend;	
					firstOnSend = firstOnSend->next;
					free(curr);
					
				}
				pthread_mutex_unlock(&WIFIDmutex);				
			}

/////////////////////////////////////////////////////////////////////////////////////////			




/*

			prevcurr = curr;
			while (curr->next){
				prevcurr = curr;
				curr = curr->next;
			}

			if (!sendData(curr)){
				pthread_mutex_lock(&WIFIDmutex);
//				printf( "freeing\n\r");				
				free(curr);
				pthread_mutex_unlock(&WIFIDmutex);
			}*/
								
		}else{
			sleep(1);
		}
	}
	return NULL;
	
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// linkedlist functions ////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
static void openFile(){
	time_t current_time;
	struct tm *loctime;
	char date_time[23];
	char location[50];
	if(global_file_write_count++ > NumberOfRecordsPerFile){ 
		file_open=0;
		fclose(fptr);
	}
	if (!file_open){
		current_time = time(NULL);
		loctime = localtime(&current_time);
		strftime (date_time, 22, "%Y-%m-%d %H:%M:%S", loctime);	
		sprintf(location,"/home/pi/data/WIFI-%s",date_time);
		fptr=fopen(location,"w");
		if(fptr){		
			global_file_write_count = 0;
			file_open=1;
		}
	}
	
}
void addWIFIDevice(const u_char *packet){
	int lengthOfAPString,i,j;
	long current_time;
	char name[31];
	int8_t rssi;
	WIFIDevice *curr;
	WIFIDevice *tcurr;
	openFile();
	lengthOfAPString = packet[0x2b];
	i = 1;
	if ( lengthOfAPString > 0 ){
		if( lengthOfAPString > MaxLengthOfAP-1 )
				lengthOfAPString = MaxLengthOfAP - 1;
		for(i = 0, j = 0x2c; i < lengthOfAPString; i++,j++){
			name[i] = packet[j];
		}
		name[i]=0;
	}
	else 
		name[0] = 0;

	current_time = time(NULL);
	fwrite(&current_time,sizeof(long),1,fptr);
	fwrite(&packet[0x1c],1,6,fptr);
	rssi = packet[0x0e] - 256;
	fwrite(&rssi,sizeof(int8_t),1,fptr);
	fwrite(name,sizeof(char),i,fptr);
	curr = (WIFIDevice *) malloc(sizeof(WIFIDevice));
	if (curr){
		memcpy(curr->mac,&packet[0x1c],6);
		strcpy(curr->AP,name);
		curr->date_time = current_time;
		curr->rssi = rssi;
		curr->next = NULL;
		pthread_mutex_lock(&WIFIDmutex);
		tcurr = firstOnSend;
		if( NULL != tcurr ){
			while( tcurr->next ){
				tcurr = tcurr->next;
			}
			tcurr->next = curr;
		} else {
			firstOnSend = curr;
		}
		pthread_mutex_unlock(&WIFIDmutex);
	}

}

//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// wifi functions //////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
void data_received(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet){
	int i=0; 
	int j = 0;
	char name[50];
	memset(name,0,50);
	
	if( header->len > 0x2b ){
		addWIFIDevice(packet);
	}
}

int scanWifi(){
		
		char dev[] = "mon0";			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "type mgt subtype probe-req";	/* The filter expression */
		bpf_u_int32 mask = 0;		/* Our netmask */
		bpf_u_int32 net = 0;		/* Our IP *ave to cast it ourselves, according to our needs in the callback function).*/
		const u_char *packet;		/* The actual packet */
		/* Define the device */
//		dev = pcap_lookupdev(errbuf);
		memset(errbuf,0x00,sizeof(errbuf));
		/* Open the session in promiscuous mode */

		
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n",dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */

		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}

		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		/* Grab a packet */
//		while(!quit)
		
		
		pcap_loop(handle, 0, data_received, NULL);
//		packet = pcap_next(handle, &header);
		/* Print its length */
		/* And close the session */
		pcap_freecode(&fp);
		pcap_close(handle);
		return(0);
}
//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// processor id ////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
void getProcessorID(){
	FILE *fptr;
    char temp[256];
    fptr = fopen("/proc/cpuinfo","r");
    while(!feof(fptr)){
        fgets(temp,256,fptr);
    }
	strncpy(cpuid,&temp[10],16);
	syslog(LOG_INFO, "CPU id : %s",cpuid);
    fclose(fptr);
}
//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// main functions //////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[]) {
	
	config_t cfg;
	char *config_file_name = "/etc/wifi-service.cfg";
	int ScanInterval, ScanWindow, TotalScanInterval;
	quit = 0;
	int rc;
	pthread_t updateThread;
	WIFIDevice * curr;

    //Set our Logging Mask and open the Log
    //setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog(DAEMON_NAME, LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);


	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = 0;
	sa.sa_handler = sigint_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

    pid_t pid, sid;

   //Fork the Parent Process
#ifdef DEMONIZE
    pid = fork();

    if (pid < 0) { exit(EXIT_FAILURE); }

    //We got a good pid, Close the Parent Process
    if (pid > 0) { exit(EXIT_SUCCESS); }
#endif
    //Change File Mask
   umask(0);

    //Create a new Signature Id for our child
//    sid = setsid();
//    if (sid < 0) { exit(EXIT_FAILURE); }

    //Change Directory
    //If we cant find the directory we exit with failure.
    if ((chdir("/")) < 0) { exit(EXIT_FAILURE); }

    //Close Standard File Descriptors
#ifdef DEMONIZE
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif
////////////////////////Getting configurations	
//	scan_ble(ScanWindow,ScanInterval,TotalScanInterval);

config_init(&cfg);

	if (!config_read_file(&cfg, config_file_name))
    {
        syslog (LOG_NOTICE, "\n%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
		syslog (LOG_NOTICE, "No configuration file found. Using default values");
	exit(0);
    } else {
 
    /* Get the configuration file name. */
    
    
	if (config_lookup_string(&cfg, "WebServiceAddress", (const char **)&WebServiceAddress)){
        syslog (LOG_NOTICE,"Web Service Address : %s", WebServiceAddress);
	}
    else{
        syslog (LOG_NOTICE,"No Web Service found in configuration file. Exiting ");
	exit(0);
	}

	
    if (config_lookup_string(&cfg, "DateFormat", (const char **)&DateFormat)){
        syslog (LOG_NOTICE,"Date and Time format : %s", DateFormat);
	}
    else{
		sprintf(DateFormat,"%%Y-%%m-%%dT%%H:%%M:%%SZ000");
        syslog (LOG_NOTICE,"No Date format found in configuration file. Using %s ",DateFormat);
	}
}
//	pthread_mutex_init(&WIFIDmutex, NULL);
	firstOnSend = NULL;
	rc = pthread_create(&updateThread, NULL, uploadData,NULL);
	
	if (rc) {
		syslog (LOG_NOTICE,"Cannot create thread to upload data exiting");
		exit(-1);
	} else {
		syslog (LOG_NOTICE,"Thread started");
	}


	getProcessorID();
	scanWifi();
	pthread_join(updateThread,NULL);
	curr = firstOnSend;
	printf("Cleaning up\n\r");
	while(curr){	
		firstOnSend = firstOnSend->next;
		free(curr);
		curr = firstOnSend;
	}		
	printf("Cleaned\n\r");
//	pthread_exit(NULL);

	pthread_mutex_destroy(&WIFIDmutex);
	syslog (LOG_NOTICE, "exiting" );
	config_destroy(&cfg);	
	//Close the log
	closelog ();
	if( file_open ){	
		fclose(fptr);
	}
	
	exit(0);
//	scanWifi();

	
 
}
