#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <map>
#include <mutex>
#define BUF_LEN 2048


typedef struct trie_node{char c; int child_size; trie_node **child;}trie_node;

char *data[1000000];
char temp[100];

int fail[700];

int failure(char word[],int n) {
	int i=0,j=-1;
	for(i=0;i<n;i++) fail[i] = -1;
	i=1;
	fail[0]=-1;
	while(i<n) {
		if(word[fail[i]+1]==word[i+1]) {
			j++;
			fail[i] = j;
			i++;
		} else if(j>-1) j=fail[j];
		else {
			i++;
		}
	}
	return 0;	
}

int KMP(char sentence[], char word[], int len) {
	failure(word,strlen(word));
	int i=0,j=-1;
	int word_len = strlen(word);
	for(i=0;i<len;i++) {
		//printf("%d %d\n",i,j);
		j++;
		if(sentence[i] == word[j]) {
			if(j==word_len-1) return i-j;
		}
		else j = fail[j];
	}
	return -1;
}

int print_host(char **host_n, u_char *buf, int size) {
	int i,j=0,k=0;
	int found = 0,len = 0;
	char get[] = {"CONNECT"};
	char host_buf[1000]={0};
	char host[100];
	if((found = KMP((char *)buf,get,size))==-1) return 0;
	sscanf((const char *)buf+found,"%s %s",host,host_buf);
	while(host_buf[len] != ' ' && host_buf[len] != '\x0d' && host_buf[len] != ':' && host_buf[len] != '\t' && host_buf[len] != '\?') len++;
	
	printf("len : %d\n",len);
	for(i=0;i<len;i++) printf("%c",host_buf[i]);
	printf("\n\n");
	*host_n = (char *)malloc(len+5);
	printf("%s\n",host_buf);
	memcpy(*host_n,host_buf,len);
	(*host_n)[len] = '\0';
	printf("copy complete\n");
	for(i=0;i<strlen(*host_n)+1;i++) printf("%d : %c\n",(*host_n)[i],(*host_n)[i]);
	printf("\n");
	printf("len : %d\n",len);
	printf("len2 : %d\n",strlen(*host_n));
	return len;
/*
	for(i=0;i<size;i++) {
		if(!found) {
			if(buf[i] == get[j]) j++;
			else j=0;
			if(j==4) {
				found = 1;
				j=0;
			}
		}
		if(!found) continue;
		if(buf[i] == host[j]) j++;
		else j=0;
		if(j!=6) continue;
		int start = ++i;
		while(buf[i]!=0x0a && buf[i]!=0x0d && i<size) i++;
		
		if(*host_n!=NULL) free(host_n);
		*host_n = (char *)malloc(sizeof(char)*(i-start+1));
		memcpy(*host_n,buf+start,i-start);
		memcpy(*host_n+i-start,"\0",1);
		
		return i-start;
	}
	return 0;*/
}

int msgcmp(char *buffer, const char *cmp) {
	int i, len = strlen(cmp);
	if(strlen(buffer)<len) return 0;
	for(i=0;i<len;i++) {
		if(buffer[i]!=cmp[i]) return 0;
	}
	return 1;
}
int child_count = 0;
int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

int create_client(int port, char *hostname)
{
    int s;
    struct sockaddr_in addr;
    struct hostent *host;
    printf("%s\n%d\n",hostname,strlen(hostname));
    if((host = gethostbyname(hostname))==NULL) {
        perror("Unable to find host address");
	exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *)(host->h_addr);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    if(connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    return s;
}
void init_openssl()
{
    system("cd cert && ./_clear_site.sh");
    system("cd cert && ./_init_site.sh");
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx, const char *str)
{
    char *buffer,*pem,*key;
    int len = strlen(str);
    SSL_CTX_set_ecdh_auto(ctx, 1);
    buffer = (char *)malloc(2*len + 200);
    
    pem = (char *)malloc(len + 30);
    key = (char *)malloc(len + 30);

    /* Set the key and cert */
    if(access("cert/..",0)< 0) {
	printf("please download cert file from https://github.com/snoopspy/cert\n");
	exit(EXIT_FAILURE);
    }
    sprintf(buffer, "cd cert && ./_make_site.sh %s",str);
    sprintf(pem, "cert/%s.pem",str);
    sprintf(key, "cert/%s.key",str);
    if(access(pem,0) < 0) {
        system(buffer);
    }

    if (SSL_CTX_use_certificate_file(ctx, pem, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

using namespace std;
map<char *, SSL_CTX *> keys;
map<char *, mutex> mutex_s;
int main() {
	int i,j;
	pid_t pid;
	struct sockaddr_in addr_in, cli_addr;
	struct hostent *host;
	int servsock,clientac,serverac;

	init_openssl();

	servsock = create_socket(4433);
	

	memset((char *)&cli_addr, 0x00, sizeof(cli_addr));
	
	int clilen = sizeof(cli_addr);

	//accepting
accepting:
	
	clientac = accept(servsock,(struct sockaddr *)&cli_addr, (unsigned int *)&clilen);
	printf("packet accepted\n");
	if(clientac < 0) {
		printf("Accepting connection error\n");
		return 0;
	}
	pid = fork();
	if(pid == 0) {
		int flag = 0, newclifd=-1, n, port=0, i, clifd;
		char *buffer;
		buffer = (char *)malloc(sizeof(char)*2010);
		char *hostname = NULL;
		char *temp = NULL;		
		char reply[] = "HTTP/1.1 200 Connection established\r\n\r\n";
		memset(buffer, 0, 2005);


		n = recv(clientac, buffer, 2000, 0);
		if(n<=0) return 0;
		buffer[n] = '\0';
		printf("/***************iqnqpquqtq*********\n");
		//printf("%s\n",buffer);	
		for(int i=0;i<n;i++) printf("%c",buffer[i]);printf("\n");
		printf("***********************************/\n");
		if(!print_host(&hostname,(u_char *)buffer, n) ) {
			printf("cannot read host name\n");
			return 0;
		}
		send(clientac, reply, strlen(reply), 0); // can connect
		printf("connection ready\n");
		//make ssl connection, context, pem,key files
		SSL_CTX *srvctx, *clictx;
		if(keys.count(hostname)>0) {
			mutex_s[hostname].lock();
			printf("already exists\n");
			srvctx = keys[hostname];
			mutex_s[hostname].unlock();
		}
		else {
			mutex_s[hostname].lock();
			printf("make new one\n");
			srvctx = create_context();
			configure_context(srvctx,hostname);
			keys[hostname] = srvctx;
			mutex_s[hostname].unlock();
		}
		if(srvctx == 0) {
			perror("Unable to create srvctx");
			exit(EXIT_FAILURE);
		}
		SSL *srvssl = SSL_new(srvctx);
		SSL_set_fd(srvssl, clientac);
		serverac = create_client(443, hostname);
		clictx = SSL_CTX_new(SSLv23_client_method());
		if(clictx == 0) {
			perror("Unable to create SSL_context");
			exit(EXIT_FAILURE);
		}
		SSL *clissl = SSL_new(clictx);
		SSL_set_fd(clissl, serverac);
		
		if(SSL_accept(srvssl) <= 0) {
			ERR_print_errors_fp(stderr);
			printf("error server\n");
			return 0;
		}
		
		if(SSL_connect(clissl) <=0) {
			ERR_print_errors_fp(stderr);
			printf("error client\n");
			return 0;
		}
		printf("finished ssl connection ready\n");	
		while(1) {
			memset(buffer, 0, 2005);
			n = SSL_read(srvssl, buffer, 2000);
			if(n<=0) break;
			buffer[n] = '\0';
			printf("/***************iqnqpquqtq*********\n");
			//printf("%s\n",buffer);	
			for(int i=0;i<n;i++) printf("%c",buffer[i]);printf("\n");
			printf("***********************************/\n");
			n = SSL_write(clissl, buffer, n);
			printf("ssl_write complete\n");
			if(memcmp(buffer+n-4, "\r\n\r\n",4)==0) break;
		}	
		printf("\tsend complete\n");
		flag = 0;
		int totlen = 0x7fffffff;
		int dellen = 0;
		char *save = buffer;
		int saven = n;
		while(1) {
			if(totlen<=0) break;
			memset(buffer,0,2005);
			n = SSL_read(clissl, buffer, 2000);
			save = buffer;
			saven = n;
			if(n<=0) break;
			//if(n!=500) flag|=2;
			buffer[n] = '\0';
			printf("////////////////////////////////////\n");
			printf("/*********oquqtqpquqtq**************\n");
//			printf("%s\n",buffer);	
			for(int i=0;i<n;i++) printf("%c",buffer[i]);printf("\n");
			printf("***********************************/\n");
			printf("////////////////////////////////////\n");

			if(KMP(buffer, "Transfer-Encoding: chunked",strlen(buffer))) {
				int pos = 0,data_len;
				if((pos = KMP(buffer, "\r\n\r\n",strlen(buffer))) ==-1 ) {
					printf("error: no chunked length data\n");
					return 0;
				}
				buffer += pos+4;
				n-= pos+4;
				sscanf(buffer, "%x",&data_len);
				int chunked_start = KMP(buffer, "\r\n", strlen(buffer));
				chunked_start +=2;
				while(data_len) {
					if(data_len + 2 > n) {
						int over_len = data_len +2 -n;
						SSL_write(srvssl,save,saven);
						n = SSL_read(clissl,buffer,2000);
						save = buffer, saven = n;
						buffer= buffer + over_len;
						n-= over_len;
					}
					else {
						buffer += data_len +2;
						n-= data_len +2;
					}
					sscanf(buffer,"%x",&data_len);
				}
				SSL_write(srvssl,save,saven);
				
					
			}
			if(flag == 0) {
				flag = 1;
				int c_len = -1;
				c_len = KMP(buffer, "Content-Length: ",strlen(buffer));
				if(c_len == -1) c_len = KMP(buffer, "content-length: ",strlen(buffer));
 
				if(c_len == -1) {
					printf("error : couldn't found content-length\n");
					n = SSL_write(srvssl,buffer,n);	
					break;
				}
				sscanf(buffer+c_len+16,"%d",&totlen);
				c_len = KMP(buffer, "\r\n\r\n",strlen(buffer));
				if(c_len == -1) break;
				totlen += c_len + 4;
				printf("\ttotal len : %d\n",totlen);
				n = SSL_write(srvssl,buffer,n);	
				totlen-=n;
			}
			else if(flag == 1){
				n = SSL_write(srvssl,buffer,n);
				totlen-=n;
			}
		}
		SSL_free(srvssl);
		SSL_free(clissl);
		close(clientac);
		close(serverac);
		printf("\tchild %d close\n",pid);
		return 0;
	}
	else {
		close(clientac);
		child_count++;
		goto accepting;
	}
	return 0;
}

