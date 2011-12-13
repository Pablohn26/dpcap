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
    unsigned char tipo;
    unsigned char codigo;
    unsigned short checksum;
    unsigned short identificador;
    unsigned short codigo;
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

void interpretar_cabeceras(const struct pcap_pkthdr *dat){
    
    
}
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
    int tcp;
    int icmp;
    int udp;
    int telnet;
    int ip;
    int ftp;
    int desconocidos;
} estadisticas;
estadisticas e;
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);//He añadido a la cabecera 
void recoger_datos_estadisticos(struct protoent*);
void mostrar_datos_estadisticos();
void tcp_mostrar();
void udp_mostrar();
void icmp_mostrar();
 /*cabeceras
  * recoger_datos_estadisticos->dentro del dispatcher_handler
  * mostrar_datos_estadisticos->cada vez que se sale del pcap_loop
  */
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
                if (pcap_loop(fp, 0, dispatcher_handler, NULL) == -1 )//con fichero, cnt = 0
                    fprintf(stderr, "Error al capturar paquetes\n");
                mostrar_datos_estadisticos();
                return 1;
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
                pcap_loop(fp,20,dispatcher_handler, NULL);//desde interfaz, cnt = 100, pero pongo 20 porque si no nos morimos esperando
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
    /* ***Usar*** pcap_lookupnet */ 
        if(pcap_lookupnet(argv[2], &direccion_red, &mascara_red, errbuf) == -1){
            fprintf (stderr, "Error al asignar el filtro");
        }

    /* Compilamos la expresión en "filtro": */ 
    /* ***Usar*** pcap_compile */
        if(pcap_compile(fp, &filtro, argv[3], 0, mascara_red) == -1){
            fprintf (stderr, "Error al compilar el filtro\n");
        }
     
    /* Establecemos un filtro para el tráfico: */  
 
    /* ***USar pcap_setfilter *** */ 
        if(pcap_setfilter(fp, &filtro) == -1){
            fprintf(stderr, "Error al asignar el filtro\n");
        }
     
    printf("Asignado filtro \"%s\"\n",argv[3]); 
  } 
 
  /* Lee y procesa tramas hasta que se llegue a EOF. */ 
  /* ***Usar*** pcap_loop; */
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
  /* print pkt timestamp and pkt len */ 
  printf("%ld : %ld (%ui)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          

  /* Comprobamos que sea un datagrama IP */ 
  trama=(ttrama_ethernet *)(pkt_data);
  if(ntohs(trama->tipo)== ETHERTYPE_IP){ 
    datagrama=(tdatagrama_ip *)(pkt_data+sizeof(ttrama_ethernet));
    ip_mostrar(*datagrama);
    recoger_datos_estadisticos(getprotobynumber(datagrama->protocolo));
  }
  else{
      fprintf(stderr, "No es un datagrama ip");
  }
  //interpretar_cabeceras(*header);

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

void recoger_datos_estadisticos(struct protoent* prt){
    if(prt->p_proto==1){
        e.icmp++;
    }else if(prt->p_proto==6){
        e.tcp++; 
    }else if(prt->p_proto==17){
        e.udp++;
    }else if(strcmp(prt->p_name, "telnet")){
        e.telnet++;
    }else if(strcmp(prt->p_name, "ftp")){
        e.ftp++;
    }else printf("Protocolo desconocido");
     
    
}

void mostrar_datos_estadisticos(){
    printf("\n \n \n");
    int total = e.icmp + e.tcp + e.udp + e.desconocidos;
    printf("Numero total de paquetes: %d\n",total);
    printf("ICMP: %d\n",e.icmp);
    printf("TCP: %d\n",e.tcp);
    printf("UDP: %d\n",e.udp);
    printf("TELNET: %d\n",e.telnet);
    printf("IP: %d\n",e.ip);
    printf("FTP: %d\n",e.ftp);
    printf("DESCONOCIDOS: %d\n",e.desconocidos);
}
