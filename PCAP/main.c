/* Pablo was here otra vez
 * Diego was here
 * File:   main.c
 * Author: diegol
 *
 * Created on 22 de noviembre de 2011, 11:25
 */

/*************************************************************************** 
 
      - jjramos, diciembre de 2004 
      - "Completo" programa de ejemplo de uso de libpcap y análisis de las 
cabeceras IP. 
      - Compilación: gcc analizador.cc -o analizador -lpcap 
 
****************************************************************************/ 
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h> 
#include <pcap.h> 
#include <string.h> 
#include <netinet/in.h> 
#include <netdb.h> 
#include <unistd.h>//Para el sleep

#define ETHERTYPE_IP 0x0800 
 
#define LINE_LEN 16 
 
#define TIPO_EN_VIVO 1 
#define TIPO_EN_FICHERO 2 
typedef struct { 
  unsigned char byte1; 
  unsigned char byte2; 
  unsigned char byte3; 
  unsigned char byte4;  
} tdireccion_ip; 

typedef struct {
   unsigned short sourceport;
    unsigned short destport;
    unsigned short longitud;
    unsigned short checksum;
    unsigned char* datos;
} tdatagrama_udp;

typedef struct {
    unsigned short sourceport;
    unsigned short destport;
    int numsecuencia;
    int ack;
    int offset_y_flags;
    unsigned short checksum;
    unsigned short pointer;
    int options_y_padding;
    unsigned char* datos;
    
} tdatagrama_tcp;

typedef struct{
    unsigned char tipo;
    unsigned char codigo;
    unsigned short checksum;
    unsigned short identificador;
    unsigned short num_secuencia;
    unsigned char* datos;
} tdatagrama_icmp;

typedef struct { 
  unsigned char version_longcabecera; /* 4 bits versio'n, 4 bits longitud de cabecera */ 
  unsigned char tos; /* Tipo de servicio */ 
  unsigned short longitud; /* longitud total del datagrama */ 
  unsigned short id; /* Identificacio'n */ 
  unsigned short indicadores_despfragmento; /* 3 bits de indicadores, 13 bits de fragmento */ 
  unsigned char ttl; /* Tiempo de vida */ 
  unsigned char protocolo; /* protocolo */ 
  unsigned short suma; /* Suma de comprobacio'n (checksum) de la cabecera */ 
  tdireccion_ip dir_origen; /* direccio'n IP del origen */ 
  tdireccion_ip dir_destino; /* direccio'n IP del destino */ 
  unsigned int opciones_relleno; /* 24 bits opciones y 8 de relleno */ 
  unsigned char *datos; 
} tdatagrama_ip; 
 
typedef struct{ 
  unsigned  char direccion_origen[6];//6 B
  unsigned char direccion_destino[6];//6 B
  unsigned short tipo;//2 B
} ttrama_ethernet;     

ip_mostrar(tdatagrama_ip datagrama) { 
  int i;
  char buffer[256];
  struct protoent *es_protocolo;
  printf(" 0                   1                   2                   3\n"); 
  printf(" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1\n"); 
  printf("+-Ver---+-HL----+-TOS-----------+-Longitud----------------------+\n"); 
  /*       version  IHL     tos             longitud */ 
  printf("| %-6d| 4x%-4d| 0x%-12x| %-30d|\n", 
       (datagrama.version_longcabecera&0xF0)>>4, 
       (datagrama.version_longcabecera&0x0F), 
       datagrama.tos, 
       ntohs(datagrama.longitud));
 
  printf("+-Id----------------------------+-Indi--+-Desp. del fragmento---+\n"); 
 
  printf("| %-30d| 0x%-4x| %-22d|\n", 
       ntohs(datagrama.id),  
       (ntohs(datagrama.indicadores_despfragmento)&0xE000)>>13,  
       (ntohs(datagrama.indicadores_despfragmento)&0x1FFF)); 
  printf("+-TTL-----------+-Protocolo-----+-Suma de comprobacio'n---------+\n"); 
 
 
  es_protocolo=getprotobynumber(datagrama.protocolo);
 
  if(es_protocolo!=0){
    sprintf(buffer,"%s",es_protocolo->p_name);
  } else { 
    sprintf(buffer,"0x%x",datagrama.protocolo); 
  } 
 
  printf("| %-14d| %-14s| 0x%-28x|\n", 
       datagrama.ttl,   
       buffer, 
       ntohs(datagrama.suma)); 
  printf("+-Direccio'n IP origen------------------------------------------+\n"); 
  printf("|                       %3d.%3d.%3d.%3d                         |\n", 
       datagrama.dir_origen.byte1, 
       datagrama.dir_origen.byte2, 
       datagrama.dir_origen.byte3, 
       datagrama.dir_origen.byte4); 
 
  printf("+-Direccio'n IP destino-----------------------------------------+\n"); 
  printf("|                       %3d.%3d.%3d.%3d                         |\n", 
       datagrama.dir_destino.byte1, 
       datagrama.dir_destino.byte2, 
       datagrama.dir_destino.byte3, 
       datagrama.dir_destino.byte4); 
  printf("+-Opciones--------------------------------------+----Relleno----+\n"); 
 
  printf("| 0x%-44x| %-14d|\n", 
       (ntohs(datagrama.opciones_relleno)&0xFFFFFF00)>>8, 
       (ntohs(datagrama.opciones_relleno)&0x000000FF)); 
  printf("+---------------------------------------------------------------+\n");
        
 
  return 0;
} 
 
typedef struct{
    int icmp;
    int udp;
    int telnet;
    int ftp;
    int desconocidos;
    int tcp;
} estadisticas;

estadisticas e;

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);//He añadido a la cabecera 
void recoger_datos_estadisticos(const char*);
void mostrar_datos_estadisticos();
void tcp_mostrar(tdatagrama_tcp* datagrama);
void udp_mostrar(tdatagrama_udp* datagrama);
void icmp_mostrar(tdatagrama_icmp* datagrama);

int mostrar_interfaces_disponibles(void){ 
  int n_interfaces=0;
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i=0;
  char errbuf[PCAP_ERRBUF_SIZE];
  printf(" Dispositivos disponibles:\n\n"); 
  /* Obtiene la lista de dispositivos: */ 
  if (pcap_findalldevs(&alldevs, errbuf) == -1 ){
      fprintf(stderr,"Error al ejecutar pcap_findalldevs");
  }
  /* Print the list */ 
  for(d=alldevs;d!=NULL;d=d->next){
      printf("\t- [%s]", d->name);
      if (d->description)
      printf(" (%s)\n", d->description);
      else
      printf(" (No hay descripción disponible)\n");
      i++;
  }
  if(i==0) 
    {
      printf("\nNo se encontraron dispositivos válidos.\n"); 
      return;
    } 
 
  /* We don't need any more the device list. Free it */ 
  pcap_freealldevs(alldevs);
  return n_interfaces;
} 
 
 
main(int argc, char **argv) { 
  estadisticas e;
  struct bpf_program filtro; 
  bpf_u_int32 mascara_red, direccion_red; 
  pcap_t *fp; 
  char errbuf[PCAP_ERRBUF_SIZE]; 
  int tipo=-1;
  if(argc < 2){ 
 
    fprintf(stderr,"Sintaxis:\n\t%s -i <interfaz de red> [filtro]\n\t%s -f <fichero de volcado> [filtro]\n\t%s -l\n\t%s -si <interfaz de red> [filtro]\n\t%s -sf <fichero de entrada> [filtro]\n", argv[0],argv[0],argv[0],argv[0],argv[0]); 
    return (-1); 
 
  } 
 
  switch(argv[1][1]){ 
  case 'i': 
    if(argc<3){
    fprintf(stderr,"Error en el paso de argumentos.\n\tSintaxis: %s -i <interfaz de red> [filtro]\n",argv[0]);   
    return 1;
    }
    //Compruebo que el dispositivo sea correcto
    
    if(check_device(argv[2])!=0){
        tipo=TIPO_EN_VIVO; 
        fp=pcap_open_live(argv[2],BUFSIZ,1,0,errbuf);
    }
    else{ 
        fprintf(stderr,"Error 4A: no existe el dispositivo %s\n",argv[2]);   
        return 1;
    }
    break; 
 
  case 'f':
 
    if(argc<3) 
      return 1; 
 
    tipo=TIPO_EN_FICHERO; 
    /* Apertura del fichero de captura */ 
    /* ***Usar***  pcap_open_offline */ 
    fp = pcap_open_offline(argv[2],errbuf);
    if (fp == NULL){
        fprintf(stderr,"Error al abrir el fichero");
    }
 
    break; 
 
  case 'l': 
        
    return mostrar_interfaces_disponibles(); 
    break;
    
  case 's':
      switch(argv[1][2]){
          case 'f':
                fp = pcap_open_offline(argv[2],errbuf);
                if (fp == NULL){
                        fprintf(stderr,"Error al abrir el fichero\n");
                }
                if (pcap_loop(fp, 0, dispatcher_handler, NULL) == -1 ){//con fichero, cnt = 0
                    fprintf(stderr, "Error al capturar paquetes\n");
                    return 1;
                }else {
                mostrar_datos_estadisticos();
                return 0;
                }                
          break;
          case 'i':
              if(argc<3){
                fprintf(stderr,"Error en el paso de argumentos.\n\tSintaxis: %s -si <interfaz de red> [filtro]\n",argv[0]);   
                return 1;
              }
              //Compruebo que el dispositivo sea correcto
   
            if(check_device(argv[2])!=0){
                tipo=TIPO_EN_VIVO; 
                fp=pcap_open_live(argv[2],BUFSIZ,1,0,errbuf);
            }
            else{ 
                fprintf(stderr,"Error 4A: no existe el dispositivo %s\n",argv[2]);   
                return 1;
            }
            while(1){
                pcap_loop(fp,500,dispatcher_handler, NULL);//desde interfaz, cnt = 100, pero pongo 20 porque si no nos morimos esperando
                mostrar_datos_estadisticos();
                sleep(5);
            }
          break;
          default: 
            fprintf(stderr,"Error: opción -%c no válida.\n",argv[1][2]); 
            return 1; 
          break; 
      }
  default: 
    fprintf(stderr,"Error: opción -%c no válida.\n",argv[1][1]); 
    return 1; 
    break; 
  } 
 
  /* En caso de que se haya especificado un filtro: */ 
  if(argc>3){ 
    /* Obtenemos cuál es la máscara de red asociada al dispositivo abierto: */ 
        if(pcap_lookupnet(argv[2], &direccion_red, &mascara_red, errbuf) == -1){
            fprintf (stderr, "Error al asignar el filtro");
        }

    /* Compilamos la expresión en "filtro": */ 
        if(pcap_compile(fp, &filtro, argv[3], 0, mascara_red) == -1){
            fprintf (stderr, "Error al compilar el filtro\n");
        }
     
    /* Establecemos un filtro para el tráfico: */  
 
        if(pcap_setfilter(fp, &filtro) == -1){
            fprintf(stderr, "Error al asignar el filtro\n");
        }
     
    printf("Asignado filtro \"%s\"\n",argv[3]); 
  } 
 
  /* Lee y procesa tramas hasta que se llegue a EOF. */ 
  if (pcap_loop(fp, 0, dispatcher_handler, NULL) == -1){
      fprintf(stderr, "Error al capturar paquetes");
  }
 
  return 0; 
} 
 
 
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
  u_int i=0;
  tdatagrama_ip *datagrama;
  tdatagrama_tcp *datagrama_tcp;
  tdatagrama_udp *datagrama_udp;
  tdatagrama_icmp *datagrama_icmp;
  ttrama_ethernet *trama;
  unsigned char longitud;
  /* print pkt timestamp and pkt len */
  printf("%ld : %ld (%ui)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          
  /* Comprobamos que sea un datagrama IP */
  trama=(ttrama_ethernet *)(pkt_data);
  if(ntohs(trama->tipo)== ETHERTYPE_IP){ 
    datagrama=(tdatagrama_ip *)(pkt_data+sizeof(ttrama_ethernet));
    ip_mostrar(*datagrama);
    longitud = 4*(datagrama->version_longcabecera & 0x0F);
    if (strcmp((getprotobynumber(datagrama->protocolo)->p_name),"tcp")){
        datagrama_tcp = (tdatagrama_tcp *) (pkt_data+sizeof(ttrama_ethernet)+longitud);
        if (datagrama_tcp->sourceport == 23){//telnet
            recoger_datos_estadisticos("telnet");
        }
        else if(datagrama_tcp->sourceport == 21){//ftp
            recoger_datos_estadisticos("ftp");
        }
        recoger_datos_estadisticos("tcp");
        tcp_mostrar(datagrama_tcp);
    }
    else if(strcmp(getprotobynumber(datagrama->protocolo)->p_name,"udp")){
        datagrama_udp = (tdatagrama_udp *) (pkt_data + sizeof(ttrama_ethernet)+longitud);
        recoger_datos_estadisticos("udp");
        udp_mostrar(datagrama_udp);
    }
    else if(strcmp(getprotobynumber(datagrama->protocolo)->p_name,"icmp")){
        datagrama_icmp = (tdatagrama_icmp *) ( pkt_data + sizeof(ttrama_ethernet)+longitud);
        recoger_datos_estadisticos("icmp");
        icmp_mostrar(datagrama_icmp);
    }
  }
  else{
      fprintf(stderr, "No es un datagrama ip");
  }

}

int check_device(const char* name){
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1 ){
      fprintf(stderr,"Error al ejecutar pcap_findalldevs dentro de check_device\n");
    }
 
    for(d=alldevs;d!=NULL;d=d->next){
        if(strcmp(name,d->name)==0){
            return 1;
        }
    }
    return 0;
}

void recoger_datos_estadisticos(const char* c){
    if(strcmp(c,"icmp") == 0){
        e.icmp++;
    }else if(strcmp(c,"telnet") == 0){
        e.telnet; 
    }else if(strcmp(c,"udp") == 0){
        e.udp++;
    }else if(strcmp(c,"ftp") == 0){
        e.ftp++;
    }else if(strcmp(c,"tcp")==0){
        e.tcp++;
    }else printf("Protocolo desconocido");
}

void mostrar_datos_estadisticos(){
    printf("\n \n \n");
    int total = e.icmp + e.udp + e.telnet +e.desconocidos;
    printf("Numero total de paquetes: %d\n",total);
    printf("ICMP: %d\n",e.icmp);
    printf("UDP: %d\n",e.udp);
    printf("TELNET: %d\n",e.telnet);
    printf("FTP: %d\n",e.ftp);
    printf("TCP: %d\n",e.tcp);
    printf("DESCONOCIDOS: %d\n",e.desconocidos);
}

void udp_mostrar(tdatagrama_udp* datagrama){
    printf("TRAMA UDP:\n");
    printf("Puerto origen : %u\n",datagrama->sourceport);
    printf("Puerto Destino: %u\n",datagrama->destport);
    printf("Longitud: %u\n",datagrama->longitud);
    printf("Suma de control: %u\n",datagrama->checksum);
}

void icmp_mostrar(tdatagrama_icmp* datagrama){
    printf("TRAMA ICMP:\n");
    printf("Tipo: %u\n",datagrama->tipo);
    printf("Codigo: %u\n",datagrama->codigo);
    printf("Suma de control: %u\n",datagrama->checksum);
    printf("Identificador: %u\n", datagrama->identificador);
    printf("Numero de Secuencia: %u\n",datagrama->num_secuencia);
}

void tcp_mostrar(tdatagrama_tcp* datagrama){
    printf("TRAMA TCP:\n");
    printf("Puerto origen : %u\n",datagrama->sourceport);
    printf("Puerto Destino: %u\n",datagrama->destport);
    printf("Numero de secuencia: %d\n",datagrama->numsecuencia);
    printf("Numero de confirmacion: %d\n",datagrama->ack);
    printf("Desplazamiento: %d\n",(datagrama->offset_y_flags & 0xF000));
    printf("Flags: %d\n",datagrama->offset_y_flags & 0x0FFF);
    printf("Suma de control: %u\n",datagrama->checksum);
    printf("Puntero urgente: %u\n",datagrama->pointer);
    printf("Opciones: %d\n",datagrama->options_y_padding & 0xFFF0);
    printf("Padding: %d\n",datagrama->options_y_padding & 0x000F);
}