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
#include <sys/poll.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>


#define DAEMON_NAME "BT Service"
#define DEMONIZE


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define DEVICE_NAME "OBP425"
#define HCI_DEVICE "hci0"
#define HCI_DEVICE_ID 0
#define VERSION 0.2

#define NUMBEROFRECORDS 1000


//#include "att.h"

//#include "textfile.h"
//#include "oui.h"

/* Unofficial value, might still change */
#define LE_LINK		0x03

#define FLAGS_AD_TYPE 0x01
#define FLAGS_LIMITED_MODE_BIT 0x01
#define FLAGS_GENERAL_MODE_BIT 0x02

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */

#define for_each_opt(opt, long, short) while ((opt=getopt_long(argc, argv, short ? short:"+", long, NULL)) != -1)

static volatile int signal_received = 0;
//static bt_uuid_t *opt_uuid = NULL;
//static GIOChannel *iochannel = NULL;
//static GMainLoop *event_loop;
static char quit = 0;

static char * DateFormat;

static char * WebServiceAddress;

static char cpuid[19];



static int alloc_count = 0;

static FILE *fptr;
static int file_open = 0;
static int global_file_write_count = 0;

static int NumberOfRecordsPerFile = 0;
static int OfflineSaving = 0;
int dev_id = 0;


static int NumberOfRecords = 1000;

static int Length = 8;


//static uint16_t X_handle;
//static uint16_t Y_handle;
//static uint16_t Z_handle;
//static bt_uuid_t X_uuid;
//static bt_uuid_t Y_uuid;
//static bt_uuid_t Z_uuid;
//static GAttrib *attrib = NULL;

//struct BLED {
//	char address[18];
//	char date_time[20];
//	struct BLED * next;
//};

struct __attribute__((__packed__)) BTD{
	long datetime;
	bdaddr_t address;
	int8_t rssi;
	uint8_t COD[3];
	char * name;
	struct BTD * next;

};
typedef struct BTD BTDevice;

BTDevice * firstOnSendList;
BTDevice * firstOnScanList;

char processorTemp[7];
char ambientTemp[7];

pthread_mutex_t Devicemutex = PTHREAD_MUTEX_INITIALIZER;


static char MajorDeviceClass[11][20]={"Misc",
				"Computer",
				"Phone",
				"LAN",
				"Audio/Video",
				"Peripheral",
				"Imaging",
				"Wearable",
				"Toy",
				"Health",
				"Uncatgorized"};
static char MinorDeviceClass[11] = {0,7,6,0x08,19,0x04,0x05,6,6,8,4};
static char CoD[11][20][30] = {	{"Miscellaneous"},
				//Computer Major
				{ "Uncategorised", "Desktop", "Server-class", "Laptop" ,"Handheld (clam)","Palmsized","Wearable","reserved"},
				//Phone Major
				{ "Uncategorised","Cellular","Cordless","Smartphone","Wired Modem","ISDN Access","Reserved"},
				//Lan/Network
				{ "Fully Available","1-17%%utilized","17-33%%utilized","33-50%%utilized","50-67%%utilized","67-83%%utilized","83-99%%utilized","No service","Reserved"},
				//Audio Video
				{ "Uncategorized","Wearable Headset","Hands-free","Reserved","Microphone","Loudspeaker","Headphones","Portable Audio","Car Audio","Set-top box","Hifi Audio","VCR","Vdieo Camera","Camcorder","Video Monitor","Video Display","Video Conferencing","Reserved","Gaming/toy","Reserved"},
 				//peripheral other
				{"Uncategorised","Joystick","Gamepad","Remote Control","Sensing Device","Digitizer tablet","Card Reader","Reserved"},
				
				//Imaging
				{"Display","Camera","Scanner","Printer","Reserved"},
				//Wearable
				{"Wrist Watch","Pager","Jacket","Helmet","Glasses","Reserved"},
				//Toy
				{"Robot","Vehicle","Doll/Action Figure","Controller","Game","Reserved"},
				//Health
				{"Undefined","BP monitor","Thermometer","Weighing Scale","Glucose Meter","Pulse Oximeter","Heart/Pulse Rate Monitor","Health Data Display","Reserved"},
				
				 //peripheral
				{ "Not keyboard/mouse","Keyboard","Pointing Device","Combo keyboard/pointing" }
				

		};
		
static char * getCOD(uint8_t * data){
	uint8_t d1,d2;
	d1 = data[1];
	d1 &= 0x1f;
	d2 = data[0];
	d2 = d2 >> 2;
	if(d1>9){
		return MajorDeviceClass[10];
	}else{
		if( d1 == 3 ) {
		 d2=d2>>3;
		} 
		if (d1 == 5){
		 if (d2 > 0x0f) {
		  d2 = d2 >> 4;
		  d1 = 10;
		 }
		}
		if (d1 == 6) {
		 int i;
		 char mask=0x04;
		 for ( i=0;i<4;i++){
		  if ( d2 & mask ){
		   break;
		   }
		   mask =mask << 1;
		 }
		 d2=i;
		}
		 if (d2 > MinorDeviceClass[d1] ){
		  d2 = MinorDeviceClass[d1];
		 }
		 return CoD[d1][d2];
	}
}



/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// Data Saving Section ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////


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
		sprintf(location,"/home/pi/data/BT-%s",date_time);
		fptr=fopen(location,"w");
		if(fptr){		
			global_file_write_count = 0;
			file_open=1;
		}
	}
	
}
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// Data upload Section ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////

static int sendIndividualDeviceData(char * data, char * WebURL, int debug){
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

		//curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT ,30); 
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 200); //timeout in seconds
		curl_easy_setopt(curl,CURLOPT_POSTFIELDS,data);

		if(debug)
 		curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);

		res = curl_easy_perform(curl);
		
		if(res != CURLE_OK){
	      		syslog(LOG_NOTICE, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
			curl_easy_cleanup(curl);

    			curl_slist_free_all(headerlist);
			curl_global_cleanup();
			if(debug)
			fclose(f);
			return 2;
		}
		curl_easy_cleanup(curl);

    		curl_slist_free_all(headerlist);
		curl_global_cleanup();
//		syslog(LOG_NOTICE, "return : 0");
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



static void * uploadData(){
	BTDevice * curr;
	BTDevice * temporary_curr;
	int i=0;
	int j = 0;
	char data[5+450*NUMBEROFRECORDS];
	char tempData[450];
	int d= 0;
//	char date_time[30];
	while(!quit){
		pthread_mutex_lock(&Devicemutex);
		curr = firstOnSendList;
		pthread_mutex_unlock(&Devicemutex);
		
		if ( curr ){
			pthread_mutex_lock(&Devicemutex);
			//curr = firstOnSendList;
			temporary_curr = curr;
			i = 0;
			while( curr && i < NumberOfRecords){
				curr = curr->next;
				i++;
			}
			data[0] = '[';
			data[1] = 0;
			curr = temporary_curr;

			for ( j = 0; j < i ; j++ ){
				uint8_t *mac;
				struct tm * loctime;
				char date_time[30];
				loctime=localtime(&curr->datetime);
				mac = (uint8_t *)&curr->address;
				strftime (date_time, 29, DateFormat, loctime);
				sprintf(tempData, "{\"Vendor\":\"\","
						"\"COD\":\"%s\","
						"\"raspberry_ID\":\"%s\","
						"\"RSSI\":%d,"
						"\"id\":\"%s\","
						"\"timestamp\":\"%s\","
						"\"DBID\":\"\","
						"\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\"},", 
						getCOD(curr->COD),
						cpuid, 
						curr->rssi,
						curr->name,
						date_time,
						mac[5],	mac[4],mac[3],mac[2],mac[1],mac[0]);
				strcat(data,tempData);
				curr = curr->next;
			}
			pthread_mutex_unlock(&Devicemutex);
			d = strlen(data);
			data[d-1] = ']';
//			syslog(LOG_NOTICE, "d = %s",data);
			if ( d > 10 && sendIndividualDeviceData(data,WebServiceAddress,1) == 0 ){
//				syslog(LOG_NOTICE, "cleaning up %d records",i);
				for ( j = 0 ; j < i; j++ ){
					curr = firstOnSendList;	
					firstOnSendList = firstOnSendList->next;
					free(curr->name);
					free(curr);
				}
				//pthread_mutex_unlock(&BLEDevicemutex);				
			}
		}
		sleep(1);
		
	}
	return NULL;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// Linked List Section ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////


static void addToFile(BTDevice * Device){
	if( OfflineSaving ){
		openFile();
		if( fptr ){
			fwrite(Device,14,1,fptr);
			//fprintf(fptr,"%s",Device->name);
		}
	}
	
}
//adds individual devices 
static void add_device_to_list(	inquiry_info_with_rssi * info_rssi ){
	BTDevice * curr;
	curr = (BTDevice *) malloc(sizeof(BTDevice));
	if (curr){
		curr->next=NULL;
		memcpy(&curr->address,&info_rssi->bdaddr,sizeof(bdaddr_t));
		curr->rssi = (int8_t)info_rssi->rssi;
		curr->datetime = time(NULL);
		curr->COD[0] = info_rssi->dev_class[0];		
		curr->COD[1] = info_rssi->dev_class[1];
		curr->COD[2] = info_rssi->dev_class[2];
		curr->next = firstOnScanList;
		addToFile(curr);
		firstOnScanList = curr;
	}
}
int bdaddcmp(bdaddr_t bdaddr1, bdaddr_t bdaddr2){
	uint8_t * one;
	uint8_t * two;
	int i;
	one = (uint8_t *)&bdaddr1;
	two = (uint8_t *)&bdaddr2;
	for( i = 0 ; i < 6 ; i++ ){
		if ( *one != *two )
			break;
		one++;
		two++;	
	}
	if ( i < 6 )
		return 1;
	else
		return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////// BT Section //////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
static void sigint_handler(int sig){
	syslog (LOG_NOTICE,"Received signal %d ",sig);
	signal_received = SIGTERM;
	quit = 1;
}


static void scanner_start()
{
	int sock = 0;
	struct hci_filter flt;
	inquiry_cp cp;
	write_inquiry_mode_cp cp1;
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	hci_event_hdr *hdr;
	char canceled = 0;
	inquiry_info_with_rssi *info_rssi;
	inquiry_info *info;
	int results, i, len;
	struct pollfd p;
	char name[248] = { 0 };
	BTDevice * curr;

//	dev_id = hci_get_route(NULL);
syslog(LOG_NOTICE,"Openingn socket");
	sock = hci_open_dev( dev_id );
	if (dev_id < 0 || sock < 0) {
		syslog(LOG_NOTICE,"Can't open socket");
		quit = 1;
		return;
	}

	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT_WITH_RSSI, &flt);
	hci_filter_set_event(EVT_INQUIRY_COMPLETE, &flt);
syslog(LOG_NOTICE,"applying filter");
	if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		syslog(LOG_NOTICE,"Can't set HCI filter");
		close(sock);
		return;
	}
while(!quit){
	cp1.mode = 1;
if (hci_send_cmd(sock, OGF_HOST_CTL, OCF_WRITE_INQUIRY_MODE, WRITE_INQUIRY_MODE_CP_SIZE, &cp1) < 0) {

		syslog(LOG_NOTICE,"Can't set inquiry mode");
		close(sock);
		return;
	}

	memset (&cp, 0, sizeof(cp));
	cp.lap[2] = 0x9e;
	cp.lap[1] = 0x8b;
	cp.lap[0] = 0x33;
	cp.num_rsp = 0;
	cp.length = Length;

//	syslog(LOG_NOTICE,"Starting inquiry with RSSI...\n");


if (hci_send_cmd (sock, OGF_LINK_CTL, OCF_INQUIRY, INQUIRY_CP_SIZE, &cp) < 0) {

		syslog(LOG_NOTICE,"Can't start inquiry");
		close(sock);
		return;
	}

	p.fd = sock;
	p.events = POLLIN | POLLERR | POLLHUP;
	canceled = 0;
	while(!canceled) {
		p.revents = 0;

		/* poll the BT device for an event */
		if (poll(&p, 1, -1) > 0) {
			len = read(sock, buf, sizeof(buf));

			if (len < 0)
				continue;
			else if (len == 0)
				break;

			hdr = (void *) (buf + 1);
			ptr = buf + (1 + HCI_EVENT_HDR_SIZE);

			results = ptr[0];

			switch (hdr->evt) {
				case EVT_INQUIRY_RESULT:
					for (i = 0; i < results; i++) {
						info = (void *)ptr + (sizeof(*info) * i) + 1;
//						print_result(&info->bdaddr, 0, 0);
					}
					break;

				case EVT_INQUIRY_RESULT_WITH_RSSI:
					for (i = 0; i < results; i++) {
						info_rssi = (void *)ptr + (sizeof(*info_rssi) * i) + 1;
						add_device_to_list(info_rssi);
					}
					break;

				case EVT_INQUIRY_COMPLETE:
					canceled = 1;
					break;
			}
		}
	}//while(!cancelled)
	//syslog(LOG_NOTICE,"Inquiry complete...\n");
	curr = firstOnScanList;
//	while ( curr ){
	//syslog(LOG_NOTICE,"Read remote name...\n");
//		if (hci_read_remote_name(sock, &curr->address, sizeof(name),name, 0) < 0)
//   						strcpy(name, "[unknown]");
//	syslog(LOG_NOTICE,"Read name complete...%s\n",name);
//		curr->name = (char *)malloc(strlen(name) + 1);
//		if(curr->name){
//			strcpy(curr->name,name);
//		}
//		
//		curr = curr->next;
//	}
	pthread_mutex_lock(&Devicemutex);
		curr = firstOnSendList;
		if( curr ){
			while(curr->next){
				curr = curr->next;
			}
			curr->next = firstOnScanList;
			firstOnScanList = NULL;
		} else {
			firstOnSendList = firstOnScanList;
			firstOnScanList = NULL;
		}
	pthread_mutex_unlock(&Devicemutex);
	
} //while(!quit)
	close(sock);
}


void scan_bluetooth(){
	
	char addr[18];
	int rc;
	pthread_t updateThread;
	BTDevice * curr;
	BTDevice * curro;


	memset(addr,0,18);
//	GError *gerr = NULL;
	
	firstOnScanList = NULL;
	firstOnSendList = NULL;
	syslog (LOG_NOTICE,"Starting Bluetooth service");
	rc = pthread_create(&updateThread, NULL, uploadData,NULL);
	
	if (rc) {
		syslog (LOG_NOTICE,"Cannot create thread to upload data exiting");
		exit(-1);
	} else {
		syslog (LOG_NOTICE,"Thread started");
	}
	while( !quit ){
		//set_state(STATE_CONNECTING);
		//
		scanner_start();
	}
	pthread_join(updateThread,NULL);
	syslog (LOG_NOTICE,"Thread Exit");
	curro = firstOnScanList;
	while(curro){	
		firstOnScanList = firstOnScanList->next;
		free(curro);
		alloc_count--;
		curro = firstOnScanList;
	}
	curr = firstOnSendList;
	while(curr){	
		firstOnSendList = firstOnSendList->next;
		free(curr);
		alloc_count--;
		curr = firstOnSendList;
	}		


}

void getprocessorID(){
	FILE *fptr;
    char temp[256];
    fptr = fopen("/proc/cpuinfo","r");
    while(!feof(fptr)){
        fgets(temp,256,fptr);
    }
	cpuid[0] = 'B';
	cpuid[1] = 'T';
	strncpy(&cpuid[2],&temp[10],16);
	syslog(LOG_INFO, "CPU id : %s",cpuid);
    fclose(fptr);
}

int main(int argc, char *argv[]) {
	
	config_t cfg;
	char *config_file_name = "/etc/btservice.cfg";
	


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
    //Change File Mask
   umask(0);

    //Create a new Signature Id for our child
    sid = setsid();
    if (sid < 0) { exit(EXIT_FAILURE); }

    //Change Directory
    //If we cant find the directory we exit with failure.
    if ((chdir("/")) < 0) { exit(EXIT_FAILURE); }

    //Close Standard File Descriptors

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif
 
	config_init(&cfg);

	if (!config_read_file(&cfg, config_file_name))
    {
        syslog (LOG_NOTICE, "\n%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
		syslog (LOG_NOTICE, "No configuration file found. Using default values");
    } else {
 
    /* Get the configuration file name. */
	if (config_lookup_int(&cfg, "NumberOfRecordsPerPost", &NumberOfRecords)){
        syslog (LOG_NOTICE,"Number of records : %d", NumberOfRecords);
	}
    else{
		NumberOfRecords = 1000;
        syslog (LOG_NOTICE,"No NumberOfRecords found in configuration file. Using 1000 ");
	}

    if (config_lookup_int(&cfg, "DeviceID", &dev_id)){
        syslog (LOG_NOTICE,"DeviceID : %d", dev_id);
	}
    else{
		dev_id = 1;
        syslog (LOG_NOTICE,"No DeviceID found in the configuration file. Using 1 ");
	}

	   
    if (config_lookup_int(&cfg, "Length", &Length)){
        syslog (LOG_NOTICE,"Length : %d", Length);
	}
    else{
		Length = 8;
        syslog (LOG_NOTICE,"No Length found in configuration file. Using 8 ");
	}
	if (config_lookup_int(&cfg, "OfflineSaving", &OfflineSaving)){
        syslog (LOG_NOTICE,"Offline Saving : %d", OfflineSaving);
	}
    else{
		OfflineSaving = 1;
        syslog (LOG_NOTICE,"No OfflineSaving found in configuration file. Enabling Offline Saving ");
	} 
	if (config_lookup_int(&cfg, "NumberOfRecordsPerFile", &NumberOfRecordsPerFile)){
        syslog (LOG_NOTICE,"Number Of Records Per File : %d", NumberOfRecordsPerFile--);
	}
    else{
		NumberOfRecordsPerFile = 119999;
        syslog (LOG_NOTICE,"No NumberOfRecordsPerFile found in configuration file. Saving 120000 Records per file.");
	} 

	
    if (config_lookup_string(&cfg, "DateFormat", (const char **)&DateFormat)){
        syslog (LOG_NOTICE,"Date and Time format : %s", DateFormat);
	}
    else{
		sprintf(DateFormat,"%%Y-%%m-%%dT%%H:%%M:%%S");
        syslog (LOG_NOTICE,"No Date format found in configuration file. Using %s ",DateFormat);
	}
	if (config_lookup_string(&cfg, "WebServiceAddress", (const char **)&WebServiceAddress)){
        syslog (LOG_NOTICE,"Web Service Address : %s", WebServiceAddress);
	}
    else{
        syslog (LOG_NOTICE,"No Web Service found in configuration file. Exiting ");
	exit(0);
	}

    
	}
	
	pthread_mutex_init(&Devicemutex, NULL);
	
	getprocessorID();
	scan_bluetooth();
	syslog (LOG_NOTICE, "exiting" );
    //Close the log
	
	if( NULL != fptr ){	
		fclose(fptr);
	}
	
	config_destroy(&cfg);
	closelog ();

	pthread_mutex_destroy(&Devicemutex);
//	pthread_exit(NULL);
	exit(0);
}
