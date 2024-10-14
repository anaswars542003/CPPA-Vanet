#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"miracl.h"

void register_vehicle(miracl* mip,big q, epoint* p, epoint* mpk, char* vpk_str );



void main(){
    miracl *mip = mirsys(5000,16);
    mip->IOBASE = 16;
    FILE* ecs = fopen("TA.ecs","r");
    
    //secp256k1 curve init
    int lsb;
    char* endptr;
    big a,b,q, generator_x,generator_y;
    char s[80];
    a = mirvar(0);
    b = mirvar(0);
    q = mirvar(0);
    generator_x = mirvar(0);
    generator_y = mirvar(0);

    cinnum(a,ecs);        // elliptic curve secp256k1 : y^2 = x^3 + 7    a = 0 , b = 7 
                       // a 

    cinnum(b,ecs);                  //b in elliptic parameter 

    cinnum(q,ecs);                   //large prime modulo   q

    fscanf(ecs, "%d",&lsb);         //least significant bit of y coordinate of generator point p
    lsb %= 2;

    fgets(s,sizeof(s),ecs);
    cinnum(generator_x,ecs);          //x coordinate of generator

    fgets(s,sizeof(s),ecs);
    cinstr(generator_y,s);          //y cordinate of generator

    ecurve_init(a,b,q, MR_PROJECTIVE);   // initialising secp256k1 curve in MIRACL system.

    // initialising curve done 
    // clearing up big numbers
    
    fclose(ecs);

    //generator point

    epoint* p;
    p = epoint_init();
    epoint_set(generator_x,generator_y,lsb,p);

    //loading TA's public key 
    big msk = mirvar(0);
    FILE* task = fopen("msk.pem","r");
    cinnum(msk,task);
    epoint* mpk = epoint_init();
    ecurve_mult(msk, p, mpk);

    char vpk[67] = "02109522f9f8c8dd091da6ace265593b7b6eb3672aa10b6574926dfd0f48645a45";
    register_vehicle(mip,q, p,mpk, vpk);

    mirexit();
}


void register_vehicle(miracl* mip,big q, epoint* p, epoint* mpk, char* vpk_str ){

    //generate c1 , c2 , c3   
    //c1 = u.P
    //c2 = u.mpk + vpk
    //c3 = u.vpk + vpk

    //Converting vpk_str to vpk point
    big vpkx ,u;
    epoint* vpk, *c1, *c2, *c3;
    vpkx = mirvar(0);
    u = mirvar(0);
    vpk = epoint_init();
    c1 = epoint_init();
    c2 = epoint_init();
    c3 = epoint_init();
    int lsb;
    
    cinstr(vpkx,vpk_str+2);
    sscanf(vpk_str,"%2d",&lsb);
    lsb %= 2;

    //set mpk point
    epoint_set(vpkx,vpkx,lsb,vpk);

    
    bigrand(q,u);  //256 bit random number;

    ecurve_mult(u,p,c1);

    ecurve_mult(u,mpk,c2);
    ecurve_add(vpk, c2);

    ecurve_mult(u, vpk, c3);
    ecurve_add(vpk, c3);

    big x,y;
    char c1_str[2][45], c2_str[2][45], c3_str[2][45];
    x = mirvar(0);
    y = mirvar(0);

    mip->IOBASE = 64;
    epoint_get(c1,x,y);
    cotstr(x,c1_str[0]);
    cotstr(y,c1_str[1]);
    printf("%s %s\n",c1_str[0],c1_str[1]);

    epoint_get(c2,x,y);
    cotstr(x,c2_str[0]);
    cotstr(y,c2_str[1]);
    printf("%s %s\n",c2_str[0],c2_str[1]);


    epoint_get(c3,x,y);
    cotstr(x,c3_str[0]);
    cotstr(y,c3_str[1]);
    printf("%s %s\n",c3_str[0],c3_str[1]);


    //printf("%s%s%s%s\n",c1_str[0],c1_str[1],c3_str[0],c3_str[1]);

    sha256 psh;
    unsigned char hash[32];
    shs256_init(&psh);
    for(int i = 0; i < 2; i++){
        for(int j = 0; c1_str[i][j] != '\0'; j++)
            shs256_process(&psh, c1_str[i][j]);
    }
    for(int i = 0; i < 2; i++){
        for(int j = 0; c3_str[i][j] != '\0'; j++)
            shs256_process(&psh, c3_str[i][j]);
    }
    shs256_hash(&psh, hash);

   //testing ASCII

    printf("%s%s%s%s\n",c1_str[0],c1_str[1],c3_str[0],c3_str[1]);

    for(int i = 0; i < 32 ; i++)
        printf("%x",hash[i]);
    
    //testing ASCII8*/

    FILE* apk;
    apk = fopen("apkeys","w");
    for(int i = 0; i < 32; i++){
        fprintf(apk,"%02x",hash[i]);
    }

    epoint_free(vpk);
    mirkill(vpkx);
    mirkill(u);
    mirkill(x);
    mirkill(y);

}