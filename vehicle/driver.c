#include<string.h>
#include<time.h>
#include"sok.h"

void read_keys_init(big sk, char* c, epoint* c1);
size_t read_message(char* msg);

int main(int argc, char* argv[])
{
    miracl* mip = mirsys(100,16);
    mip->IOBASE = 16;
    char* a_str = "0000000000000000000000000000000000000000000000000000000000000000";
    char* b_str = "0000000000000000000000000000000000000000000000000000000000000007";
    char* q_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    char* x_str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    char* y_str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    char* n_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    sok_signature sig;
    big a = mirvar(0);
    big b = mirvar(0);
    big q = mirvar(0);

    cinstr(a, a_str);
    cinstr(b, b_str);
    cinstr(q, q_str);
    ecurve_init(a,b,q,MR_PROJECTIVE);
    cinstr(a, x_str);
    cinstr(b, y_str);
    epoint* p = epoint_init();
    int n = epoint_set(a,b,1,p);
    cinstr(q, n_str);
    
    

    big sk = mirvar(0);
    epoint* c1 = epoint_init();
    unsigned char c[128];
    
    char msg[200];
    size_t msg_size;
    int t = 0;
    
    //use a file with sk,c1_x,c1_y,c2_x,c2_y stored in continuos byte stream. (read using "rb")
    
    read_keys_init(sk, c, c1);
    msg_size = read_message(msg);
    //recieved APK , sk and message to generate proof
    
    clock_t start;
    clock_t end;

    start = clock();
    for(int i = 0 ; i < 100; i++){
        genProof(mip, q, p, sk, c, msg, msg_size, t, &sig);
    }
    end = clock();
    double time_taken = (double)(end - start)/CLOCKS_PER_SEC;
    printf("Time for signing 100 messages: %f\n",time_taken);
    printf("Average time : %f\n", time_taken/100);
    


    start = clock();
    for(int i = 0 ; i < 100; i++){
        n = verifyProof(mip, q, p, c, msg, msg_size, t, &sig);
    }
    end = clock();
    time_taken = (double)(end - start)/CLOCKS_PER_SEC;
    printf("Time for signing 100 messages: %f\n",time_taken);
    printf("Average time : %f\n", time_taken/100);
    
    n ? printf("TRUE") : printf("FALSE");

    /*printf("\nz:");
    for(int i = 0; i < 32; i++){
        printf("%02x",sig.z[i]);
    }
    printf("\nRx:");
    for(int i = 0; i < 32; i++){
        printf("%02x",sig.Rx[i]);
    }
     printf("\nRy:");
    for(int i = 0; i < 32; i++){
        printf("%02x",sig.Ry[i]);
    }*/

   
    
    //printf("%f\n",cpu_time_used);
    epoint_free(c1);
   //epoint_free(c2);
    epoint_free(p);
    mirkill(sk);
    mirkill(a);
    mirkill(b);
    mirkill(q);
    mirexit();
    return 0;
}

void read_keys_init(big sk, char* c, epoint* c1)
{
    big a = mirvar(0);
    big b = mirvar(0);
    FILE* f = fopen("apk.key","rb");
    fread(c, 32, 1, f);
    bytes_to_big(32, c, sk);
    fread(c, 32, 4, f);
    bytes_to_big(32, c, a);
    bytes_to_big(32, c+32, b);
    int n = epoint_set(a,b,0,c1);


    fclose(f);
    mirkill(a);
    mirkill(b);
}

size_t read_message(char* msg)
{
    char a[] = "HELLO WORLDASDWASDAANJJ";
    strcpy(msg, a);
    return sizeof(a);
}