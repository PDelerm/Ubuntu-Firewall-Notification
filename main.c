#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void SIGIO_handler(){
	printf("test \n");
}

void createRule(int file){
	char buffer[256], *buffer2;
	
	lseek(file, 0, SEEK_CUR);
	read(file, buffer, 255*sizeof(char));
	printf("%s \n", buffer);
	
	buffer2 = strtok(buffer, "=");
	printf("%s \n", buffer2);

	//printf("sudo insert allow proto %s from %s to any port %d \n", protocole, source, port);
	//execlp();
}

int main(){
	int file = open("/var/log/ufw.log", O_RDONLY | O_NONBLOCK | O_ASYNC);	// poll(2) select(2)
			signal(SIGIO, SIGIO_handler);
	if(file != -1){
		int f = fcntl(file, F_SETFL, O_ASYNC | O_NONBLOCK);
		if(f != -1){
			while(1){
				sleep(1); // sigsuspend()
			}
		}
		else{
			perror("fcntl");
			exit(1);
		}
	}
	else
		printf("ERROR OF OPPENNING \n");
	return 0;
}
