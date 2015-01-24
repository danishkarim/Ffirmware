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

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>


#define DAEMON_NAME "ble Service"
//#define DEMONIZE


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define DEVICE_NAME "OBP425"
#define HCI_DEVICE "hci0"
#define HCI_DEVICE_ID 0
#define VERSION 0.2


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

static char sScanInterval[10], sScanWindow[10], sTotalScanInterval[10];

static char cpuid[17];

static int GlobalCount = 0;

//static uint16_t X_handle;
//static uint16_t Y_handle;
//static uint16_t Z_handle;
//static bt_uuid_t X_uuid;
//static bt_uuid_t Y_uuid;
//static bt_uuid_t Z_uuid;
//static GAttrib *attrib = NULL;

struct BLED {
	char address[18];
	char date_time[20];
	struct BLED * next;
};

struct NoBLED{
	char date_time[20];
	int count;
	struct NoBLED * next;
};
typedef struct NoBLED nobled;
typedef struct BLED BLEDevice;
//struct BLEDevice bledevices;

BLEDevice * firstOnScanList;
BLEDevice * firstOnSendList;
nobled * firstOnScan;
nobled * firstOnSend;

pthread_mutex_t BLEDmutex = PTHREAD_MUTEX_INITIALIZER;

static int sendData(nobled * curr, char * processorTemp, char * ambientTemp){
	CURL *curl;
	CURLcode res;
	char count[10];
 
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	//struct curl_slist *headerlist=NULL;
	//static const char buf[] = "Expect:";
	
	FILE *f = fopen("/dev/null", "wb");
 
	curl_global_init(CURL_GLOBAL_ALL);

	sprintf(count,"%d",curr->count);

// add time 
//	syslog(LOG_NOTICE,"Uping the data %s",curr->date_time);
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.2131414051",
               CURLFORM_COPYCONTENTS, curr->date_time,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done time");
//add cpu id
//	syslog(LOG_NOTICE,"cpuid %s",cpuid);
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.282589390",
               CURLFORM_COPYCONTENTS, cpuid,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done cpuid");
//Globalcount or tags detected
//	syslog(LOG_NOTICE,"cpuid %s",count);
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.963152313",
               CURLFORM_COPYCONTENTS, count,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done count");
//Scanning window
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.905272969",
               CURLFORM_COPYCONTENTS, sScanWindow,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done scan window");
//Scanning interval
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.1787824130",
               CURLFORM_COPYCONTENTS, sScanInterval,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done scan interval");
//Whole window or total scan interval
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.148908309",
               CURLFORM_COPYCONTENTS, sTotalScanInterval,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done total interval");
//Processor temp
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.559761392",
               CURLFORM_COPYCONTENTS, processorTemp,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done proc temp");
//Ambient temp
	curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "entry.823729544",
               CURLFORM_COPYCONTENTS, ambientTemp,
               CURLFORM_END);
//	syslog(LOG_NOTICE,"Uping done ambient");
	
 
	curl = curl_easy_init();
	//headerlist = curl_slist_append(headerlist, buf);

	if(curl) {

	    curl_easy_setopt(curl, CURLOPT_URL, "https://docs.google.com/forms/d/1A3X9CIAWuqVcRj__CRORF963dJrTJPKzmIgC1X2XU2o/formResponse");

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
//	syslog(LOG_NOTICE, "upped the data");
		return 0;
  	}else{
//		syslog(LOG_NOTICE, "upped the data");
		fclose(f);
		return 1;
	}
}

static int getAmbientTemp(char * temp){
	DIR *dir;
	struct dirent *dirent;
	char dev[16];      // Dev ID
	char devPath[128]; // Path to device
	char buf[256];     // Data from device
	char tmpData[6];   // Temp C * 1000 reported by device 
	char path[] = "/sys/bus/w1/devices"; 
	ssize_t numRead;
	char notemp[] = "notemp";
	strcpy(temp,notemp);
	dir = opendir (path);
	if (dir != NULL){
		while ((dirent = readdir (dir)))
		if (dirent->d_type == DT_LNK && 
			strstr(dirent->d_name, "28-") != NULL) { 
			strcpy(dev, dirent->d_name);
//			syslog(LOG_INFO,"Device found at %s", dev);
		}
		(void) closedir (dir);
    }
	else{
		perror ("Couldn't open the w1 devices directory ");
		return 1;
	}
	sprintf(devPath, "%s/%s/w1_slave", path, dev);
	int fd = open(devPath, O_RDONLY);
	if(-1 == fd){
		perror ("Couldn't open the w1 device.");
		return 1;
	}
	while((numRead = read(fd, buf, 256)) > 0) {
		strncpy(tmpData, strstr(buf, "t=") + 2, 5);
		strncpy(temp,tmpData,2);
		temp[2] = '.';
		strncpy(&temp[3],&tmpData[2],3);	
	}
	close(fd);
	return 0;
}

static void getProcessorTemp(char * temp){
	    FILE *fptr;
		char buff[10];
        fptr = fopen("/sys/class/thermal/thermal_zone0/temp","r");
		if(fptr){
	        fscanf(fptr,"%s",buff);
			strncpy(temp,buff,2);
			temp[2] = '.';
			strncpy(&temp[3],&buff[2],3);
		}
		temp[6] = '\0';
        fclose(fptr);
}

static void * uploadData(){
//	BLEDevice * curr;
	nobled * curr;
	char processorTemp[7];
	char ambientTemp[7];
	while(!quit){
//		if ( firstOnSendList ){
//			curr = firstOnSendList;	
//			if (!sendData(curr)){
//				pthread_mutex_lock(&BLEDmutex);
//				firstOnSendList = firstOnSendList->next;
//				free(curr);
//				pthread_mutex_lock(&BLEDmutex);
//			}
//		}

		
		if ( firstOnSend ){
			getProcessorTemp(processorTemp);
			//sprintf(ambientTemp,"34.444");
			getAmbientTemp(ambientTemp);
//			temp = (nobled *)malloc(sizeof(nobled);
//			if (temp){
			
				pthread_mutex_lock(&BLEDmutex);
				curr = firstOnSend;
				if (!sendData(curr,processorTemp,ambientTemp)){
					firstOnSend = firstOnSend->next;
					free(curr);
				}
				pthread_mutex_unlock(&BLEDmutex);
//			}
								
		}else{
			sleep(15);
		}
	}
	pthread_mutex_lock(&BLEDmutex);
	curr = firstOnSend;
	while(curr){	
		firstOnSend = firstOnSend->next;
		free(curr);
		curr = firstOnSend;
	}		
	pthread_mutex_unlock(&BLEDmutex);
	pthread_exit(NULL);
}

static nobled * addToList_nobled(nobled * head, int count, char *date_time){
	nobled * curr;
	curr = (nobled *) malloc(sizeof(nobled));
	if (curr){
		curr->count = count;
		strcpy(curr->date_time,date_time);
		curr->next = head;
		return curr;
	}
	return head;
}


static void addDeviceCountToUpload(struct tm *loctime){
	char date_time[25];
//	syslog (LOG_NOTICE,"Adding to upload ");
	while(pthread_mutex_trylock(&BLEDmutex) != 0);
	strftime (date_time, 22, "%Y-%m-%d %H:%M:%S", loctime);
//	syslog(LOG_NOTICE,"done with datetime");

//	syslog (LOG_NOTICE,"adding right now");
	firstOnSend = addToList_nobled(firstOnSend,GlobalCount,date_time);
	pthread_mutex_unlock(&BLEDmutex);
}

static BLEDevice * addToList(BLEDevice * head, char * address, char * date_time){
	BLEDevice * curr;
	curr = (BLEDevice *) malloc(sizeof(BLEDevice));
	if (curr){
		strcpy(curr->address,address);
		strcpy(curr->date_time,date_time);
		curr->next = head;
		return curr;
	}
	return head;
}

void checkDeviceAndAdd(char * address){
	BLEDevice * curr;
	char date_time[22];
	time_t current_time;
	struct tm *loctime;
	
	curr = firstOnScanList;
	while ( curr ){
		if (strcmp(address,curr->address) == 0)
			break;
		curr = curr->next;
	}
	if (NULL == curr){
		current_time = time(NULL);
		loctime = localtime(&current_time);
		strftime (date_time, 22, "%Y-%m-%d %H:%M:%S", loctime);
//		syslog (LOG_NOTICE,"Adding %s ",address);
		//pthread_mutex_lock(&BLEDmutex);
		firstOnScanList = addToList(firstOnScanList, address, date_time);
		//pthread_mutex_unlock(&BLEDmutex);		
		GlobalCount++;
	}
}

//////////////////////////////////////// BLE functions ///////////////////////////////////////////
static void sigint_handler(int sig){
	syslog (LOG_NOTICE,"Received signal %d ",sig);
	signal_received = SIGTERM;
	quit = 1;
}

static int read_flags(uint8_t *flags, const uint8_t *data, size_t size)
{
	size_t offset;

	if (!flags || !data)
		return -EINVAL;

	offset = 0;
	while (offset < size) {
		uint8_t len = data[offset];
		uint8_t type;

		/* Check if it is the end of the significant part */
		if (len == 0)
			break;

		if (len + offset > size)
			break;

		type = data[offset + 1];

		if (type == FLAGS_AD_TYPE) {
			*flags = data[offset + 2];
			return 0;
		}

		offset += 1 + len;
	}

	return -ENOENT;
}

static int check_report_filter(uint8_t procedure, le_advertising_info *info)
{
	uint8_t flags;

	/* If no discovery procedure is set, all reports are treat as valid */
	if (procedure == 0)
		return 1;

	/* Read flags AD type value from the advertising report if it exists */
	if (read_flags(&flags, info->data, info->length))
		return 0;

	switch (procedure) {
	case 'l': /* Limited Discovery Procedure */
		if (flags & FLAGS_LIMITED_MODE_BIT)
			return 1;
		break;
	case 'g': /* General Discovery Procedure */
		if (flags & (FLAGS_LIMITED_MODE_BIT | FLAGS_GENERAL_MODE_BIT))
			return 1;
		break;
	default:
		fprintf(stderr, "Unknown discovery procedure\n");
	}

	return 0;
}
static void eir_parse_name(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len)
{
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			name_len = field_len - 1;
			if (name_len > buf_len)
				goto failed;

			memcpy(buf, &eir[2], name_len);
			return;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}

failed:
	snprintf(buf, buf_len, "(unknown)");
}


static int cmd_lescan(int dev_id,char *addr,uint16_t window, uint16_t interval, uint16_t TotalScanInterval)
{
	int err, dd;
	uint8_t own_type = 0x00;
	uint8_t scan_type = 0x01;
	uint8_t filter_type = 0x00;
	uint8_t filter_policy = 0x00;
	interval = interval * 8;
	interval = interval / 5;
	interval = htobs(interval);
	window = window * 8;
	window = window / 5;
	window = htobs(window);
	uint8_t filter_dup = 0x01;
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	BLEDevice * curr;	
	socklen_t olen;
	int len;
	int returnValue = 0;
	time_t current_time;
	struct tm *loctime;
	olen = sizeof(of);
	fd_set set;
	struct timeval timeout;
	int rv;

	if (dev_id < 0)
		dev_id = hci_get_route(NULL);

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		syslog (LOG_NOTICE,"Could not open device");
		exit(1);
	}
	err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
						own_type, filter_policy, 1000);
	if (err < 0) {
		syslog (LOG_NOTICE,"Set scan parameters failed. Trying to close and then open the hci device.");
		hci_close_dev(dd);
		dd = hci_open_dev(dev_id);
		if (dd < 0) {
			syslog (LOG_NOTICE,"Could not open device");
			exit(1);
		}
		err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
						own_type, filter_policy, 1000);
		if( err > 0 ){
			syslog (LOG_NOTICE,"Still could not set the scan parameters");
			exit(1);
		}
	}
//sleep(10);
	err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 1000);
	if (err < 0) {
		syslog (LOG_NOTICE,"Enable scan failed");
		return -1;
	}


// searching for OLP425

	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
		syslog (LOG_NOTICE,"Could not get socket options\n");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);


	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		syslog (LOG_NOTICE,"Could not set socket options\n");
		exit(1);
	}
	//syslog (LOG_NOTICE,"Done all\n");	

	current_time = time(NULL);
//	syslog (LOG_NOTICE, "entering at %s ", ctime(&current_time));
	current_time += TotalScanInterval;

	FD_ZERO(&set);
	FD_SET(dd, &set);

	timeout.tv_sec = TotalScanInterval;
	timeout.tv_usec = 0;
	while (current_time > time(NULL)) {
		evt_le_meta_event *meta;
		le_advertising_info *info;
		//char addr[18];
		rv=select(dd+1, &set,NULL,NULL,&timeout);
		if( -1 == rv ){
			syslog(LOG_ERR,"select error");
			goto done;
		}
		else if ( 0 == rv ){
			syslog(LOG_ERR,"Timeout");
			goto done;
		} else {
			len = read(dd, buf, sizeof(buf));
		}
//		while ((len = read(dd, buf, sizeof(buf))) < 0) {
//			printf( "len %d \n\r", len);
//			if (errno == EINTR && signal_received == SIGTERM ) {
//				len = 0;
//				returnValue = 1;
//				goto done;
//			}

//			if (errno == EAGAIN || errno == EINTR)
//				continue;
//			goto done;
//		}

		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		meta = (void *) ptr;

		if (meta->subevent != 0x02)
			goto done;
		/* Ignoring multiple reports */
		info = (le_advertising_info *) (meta->data + 1);
		if (check_report_filter(filter_type, info)) {
			char name[30];

			memset(name, 0, sizeof(name));

			ba2str(&info->bdaddr, addr);
			eir_parse_name(info->data, info->length,
							name, sizeof(name) - 1);
			
//			syslog (LOG_NOTICE,"%s %s\n", addr, name);
			checkDeviceAndAdd(addr);
		}
	}

done:

//	curr = firstOnScanList;
//	if( firstOnScanList ){
//			curr = firstOnScanList;
//			while( curr ){
				//syslog (LOG_NOTICE,"address %s, time %s", curr->address,curr->date_time);
//				if( curr->next ){
//					curr = cur->next;
//				} else {
//					break;
//				}
//			}
//			pthread_mutex_lock(&BLEDmutex);
//			curr->next = firstOnSendList;
//			firstOnSendList = firstOnScanList;
//			firstOnScanList = NULL;
//			pthread_mutex_unlock(&BLEDmutex);
//	}
	//current_time = time(NULL);
//	syslog(LOG_NOTICE,"done");
	loctime = localtime(&current_time);
	//strftime (date_time, 22, "%Y-%m-%d %H:%M:%S", loctime);
	addDeviceCountToUpload(loctime);
	GlobalCount = 0;
	curr = firstOnScanList;
//	syslog (LOG_NOTICE,"added device count to upload");
	while ( curr ){
		firstOnScanList = curr->next;
		free(curr);
		curr = firstOnScanList;
	}

	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	
	

	err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 1000);
	//printComment("Disabling Scan ...");
	//syslog (LOG_NOTICE,"Disabling scan");
	if (err < 0) {
		syslog (LOG_NOTICE,"Disable scan failed");
//		exit(1);
	}

	hci_close_dev(dd);
	if (len < 0){
		syslog (LOG_NOTICE,"length less than zero");
		//exit(1);
	}
	return returnValue;
	
}

void scan_ble(int ScanWindow,int ScanInterval, int TotalScanInterval){
	int dev_id = HCI_DEVICE_ID;
	char addr[18];
	int rc;
	pthread_t updateThread;


	memset(addr,0,18);
//	GError *gerr = NULL;
	
	firstOnScanList = NULL;
	firstOnSendList = NULL;
	firstOnSend = NULL;
	firstOnScan = NULL;
	syslog (LOG_NOTICE,"Starting BLE service");
	rc = pthread_create(&updateThread, NULL, uploadData,NULL);
	
	if (rc) {
		syslog (LOG_NOTICE,"Cannot create thread to upload data exiting");
		exit(-1);
	} else {
		syslog (LOG_NOTICE,"Thread started");
	}
	while( !quit ){
		//set_state(STATE_CONNECTING);
		cmd_lescan(dev_id,addr,ScanWindow,ScanInterval,TotalScanInterval);
	}


}

void getprocessorID(){
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

int main(int argc, char *argv[]) {
	
	config_t cfg;
	char *config_file_name = "/etc/ble-service.cfg";
	int ScanInterval, ScanWindow, TotalScanInterval;
	


    //Set our Logging Mask and open the Log
    //setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog(DAEMON_NAME, LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);

    syslog(LOG_ERR, "Entering Daemon");

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = 0;
	sa.sa_handler = sigint_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

    pid_t pid, sid;

   //Fork the Parent Process
//#ifdef DEMONIZE
    pid = fork();

    if (pid < 0) { exit(EXIT_FAILURE); }

    //We got a good pid, Close the Parent Process
    if (pid > 0) { exit(EXIT_SUCCESS); }
//#endif
    //Change File Mask
   umask(0);

    //Create a new Signature Id for our child
    sid = setsid();
    if (sid < 0) { exit(EXIT_FAILURE); }

    //Change Directory
    //If we cant find the directory we exit with failure.
    if ((chdir("/")) < 0) { exit(EXIT_FAILURE); }

    //Close Standard File Descriptors
//#ifdef DEMONIZE
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
//#endif
 
	config_init(&cfg);

	if (!config_read_file(&cfg, config_file_name))
    {
        syslog (LOG_NOTICE, "\n%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
		syslog (LOG_NOTICE, "No configuration file found. Using default values");
    } else {
 
    /* Get the configuration file name. */
    if (config_lookup_int(&cfg, "ScanWindow", &ScanWindow)){
        syslog (LOG_NOTICE,"Scan window : %d", ScanWindow);
	}
    else{
		ScanWindow = 10;
        syslog (LOG_NOTICE,"No ScanWindow found in configuration file. Using 10ms ");
	}
 
    if (config_lookup_int(&cfg, "ScanInterval", &ScanInterval)){
        syslog (LOG_NOTICE,"Scan Interval : %d", ScanInterval);
	}
    else{
		ScanInterval = 10;
        syslog (LOG_NOTICE,"No ScanIntervalfound in configuration file. Using 10ms ");
	}
	   
    if (config_lookup_int(&cfg, "TotalScanInterval", &TotalScanInterval)){
        syslog (LOG_NOTICE,"Total Scan Interval : %d", TotalScanInterval);
	}
    else{
		TotalScanInterval = 10;
        syslog (LOG_NOTICE,"No TotalScanInterval found in configuration file. Using 10s ");
	}

    config_destroy(&cfg);
	}
	pthread_mutex_init(&BLEDmutex, NULL);
	
	getprocessorID();
	sprintf(sScanWindow,"%d",ScanWindow);
	sprintf(sScanInterval,"%d",ScanInterval);
	sprintf(sTotalScanInterval,"%d",TotalScanInterval);	
	scan_ble(ScanWindow,ScanInterval,TotalScanInterval);
	syslog (LOG_NOTICE, "exiting" );
    //Close the log
    closelog ();
	pthread_mutex_destroy(&BLEDmutex);
	pthread_exit(NULL);
	exit(0);
}
