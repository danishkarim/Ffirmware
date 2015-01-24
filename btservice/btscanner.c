
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>


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
		
static char * getCOD(char * data){
	uint8_t d1,d2;
	int coddata;
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


static void print_result1(bdaddr_t *bdaddr, char has_rssi, int rssi,char * name, inquiry_info_with_rssi *info){
	char addr[18];
	char Major;
	int i;
	char mask = 0x01;

	Major = info->dev_class[2];
	for(i = 0 ; i < 8; i++ ){
		if( Major & mask )
			break;
	}	
	if ( i < 8 ){
		i += 2;
	}else{
		i = 0;
	}

	ba2str(bdaddr, addr);

	printf("%17s", addr);
	if(has_rssi)
		printf(" RSSI:%d", rssi);
	else
		printf(" RSSI:n/a");
	printf(" %s ",name);
	printf(" %s  %02X %02X %02X",getCOD(info->dev_class),info->dev_class[0],info->dev_class[1],info->dev_class[2]);
	printf("\n");
	//fflush(NULL);	
}
static void print_result(bdaddr_t *bdaddr, char has_rssi, int rssi,char * name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	printf("%17s", addr);
	if(has_rssi)
		printf(" RSSI:%d", rssi);
	else
		printf(" RSSI:n/a");
	printf(" %s ",name);
	printf("\n");
	fflush(NULL);
}


static void scanner_start()
{
	int dev_id, sock = 0;
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

	dev_id = hci_get_route(NULL);
	sock = hci_open_dev( dev_id );
	if (dev_id < 0 || sock < 0) {
		perror("Can't open socket");
		return;
	}

	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT, &flt);
	hci_filter_set_event(EVT_INQUIRY_RESULT_WITH_RSSI, &flt);
	hci_filter_set_event(EVT_INQUIRY_COMPLETE, &flt);
	if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		perror("Can't set HCI filter");
		return;
	}

	cp1.mode = 1;
if (hci_send_cmd(sock, OGF_HOST_CTL, OCF_WRITE_INQUIRY_MODE, WRITE_INQUIRY_MODE_CP_SIZE, &cp1) < 0) {

		perror("Can't set inquiry mode");
		return;
	}

	memset (&cp, 0, sizeof(cp));
	cp.lap[2] = 0x9e;
	cp.lap[1] = 0x8b;
	cp.lap[0] = 0x33;
	cp.num_rsp = 0;
	cp.length = 0x05;

	printf("Starting inquiry with RSSI...\n");

if (hci_send_cmd (sock, OGF_LINK_CTL, OCF_INQUIRY, INQUIRY_CP_SIZE, &cp) < 0) {

		perror("Can't start inquiry");
		return;
	}

	p.fd = sock;
	p.events = POLLIN | POLLERR | POLLHUP;

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
						print_result(&info->bdaddr, 0, 0,"test");
					}
					break;

				case EVT_INQUIRY_RESULT_WITH_RSSI:
					for (i = 0; i < results; i++) {
						info_rssi = (void *)ptr + (sizeof(*info_rssi) * i) + 1;
						memset(name, 0, sizeof(name));
						print_result1(&info_rssi->bdaddr, 1, info_rssi->rssi,"two",info_rssi);
					}
					break;

				case EVT_INQUIRY_COMPLETE:
					canceled = 1;
					break;
			}
		}
	}
	if (hci_read_remote_name(sock, &info_rssi->bdaddr, sizeof(name), 
            						name, 0) < 0)
        						strcpy(name, "[unknown]");
	print_result1(&info_rssi->bdaddr, 1, info_rssi->rssi,name,info_rssi);

	close(sock);
}

int main(int argc, char **argv)
{
	int i; /* causes inq. result to have no rssi value */
	scanner_start();
	return 0;
}
