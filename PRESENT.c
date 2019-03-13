//////////////////////////////////////////////////////
//                                                  //
//  Lightweight block cipher PRESENT implementation //
//  Authors:                                        //
//  Petar Tonkovikj                                 //
//  Kristina Cvetanovska                            //
//  Gorazd Nikolovski                               //
//                                                  //
//////////////////////////////////////////////////////

#include <stdio.h>
#include<stdint.h>

// define a byte structure consisted of two 4 bit nibbles
// the structure has packed attributes (prevent the compiler from adding padding in memory between them)
typedef struct __attribute__((__packed__)) byte{
    uint8_t nibble1 : 4;
    uint8_t nibble2 : 4;
} byte;
// define the SBox
uint8_t S[] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
// define the inverse SBox
uint8_t invS[] = {0x5, 0xe, 0xf, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};
// define the permutation table
uint8_t P[] = {0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
                    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
                    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
                    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63};
// function for converting a Hex String to an array of bytes
byte* fromHexStringToBytes (char *block){
    byte* bytes = malloc(8 * sizeof(byte));
    int i;
    // each character of the String is one nibble (4 bits), there are 8 bytes in a 64-bit block
    for (i=0; i<8; i++){
        bytes[i].nibble1 = (block[2*i]>='0' && block[2*i]<='9')? (block[2*i] - '0') : (block[2*i] - 'a' + 10);
        bytes[i].nibble2 = (block[2*i+1]>='0' && block[2*i+1]<='9')? (block[2*i+1] - '0') : (block[2*i+1] - 'a' + 10);
    }
    return bytes;
}
// function for converting an array of bytes to a 64-bit integer
uint64_t fromBytesToLong (byte* bytes){
    uint64_t result = 0;
    int i;
    // multiplication with 16 replaced with shifting right 4 times
    // addition replaced with bitwise OR, since one of the operands is always 0
    for (i=0; i<8; i++){
        result = (result << 4) | (bytes[i].nibble1 & 0xFUL);
        result = (result << 4) | (bytes[i].nibble2 & 0xFUL);
    }
    return result;
}
// function for converting Hex String to a 64-bit integer
uint64_t fromHexStringToLong (char* block){
    uint64_t result;
    int i;
    // each character is 4 bits, there are 16 characters in a 64-bit block
    // the multiplication and addition are done the same way as before, with shifting and bitwise OR
    for (i=0; i<16; i++)
        result = (result << 4) | ((block[i]>='0' && block[i]<='9')? (block[i] - '0') : (block[i] - 'a' + 10));
    return result;
}
// function for converting a 64-bit integer to an array of bytes
byte* fromLongToBytes (uint64_t block){
    byte* bytes = malloc (8 * sizeof(byte));
    int i;
    // the nibbles for each byte are obtained by shifting the number to the right for appropriate number of places (a multiple of 4)
    // each nibble is obtained after masking the bits by performing bitwise AND with 1111 (all bits except the least significant 4 become 0)
    for (i=7; i>=0; i--){
        bytes[i].nibble2 = (block >> 2 * (7 - i) * 4) & 0xFLL;
        bytes[i].nibble1 = (block >> (2 * (7 - i) + 1) * 4) & 0xFLL;
    }
    return bytes;
}
// function for converting a 64-bit integer to a Hex String
char* fromLongToHexString (uint64_t block){
    char* hexString = malloc (17 * sizeof(char));
    //we print the integer in a String in hexadecimal format
    sprintf(hexString, "%016llx", block);
    return hexString;
}
// function for converting a nibble using the SBox
uint8_t Sbox(uint8_t input){
    return S[input];
}
// inverse function of the one above (used to obtain the original nibble)
uint8_t inverseSbox(uint8_t input){
    return invS[input];
}
/*
    function that performs the permutation according to the permutation table P

    The permutation is done by adding one bit at a time from the source block to the appropriate location in the result.
    In each iteration the following is performed:
    1) calculate the distance of the bit that is supposed to be added next from the least significant bit (at position 63)
    2) shift the source block to the right so that the bit becomes the least significant bit
    3) separate this bit by masking by performing bitwise and with 1
    4) calculate the new location (from right to left) of the bit (distance between the least significant bit and P[i])
    5) shift the bit to the new location and add it to the permutation using bitwise OR
*/
uint64_t permute(uint64_t source){
    uint64_t permutation = 0;
    int i;
    for (i=0; i<64; i++){
        int distance = 63 - i;
        permutation = permutation | ((source >> distance & 0x1) << 63 - P[i]);
    }
    return permutation;
}
/*
    function that performs the inverse permutation according to the table P

    Again, the permutation is done by adding one bit at a time to the result.
    In each iteration the following is performed:
    1) calculate the position of the bit that should be on the i-th position
    2) shift the result 1 bit to the left (i-th bit of the final permutation is on the least significant location)
    3) shift the source block so that the needed bit comes to the least significant location
    4) separate this bit by masking by performing bitwise and with 1
    5) add it to the (inverse)permutation using bitwise OR
*/
uint64_t inversepermute(uint64_t source){
    uint64_t permutation = 0;
    int i;
    for (i=0; i<64; i++){
        int distance = 63 - P[i];
        permutation = (permutation << 1) | ((source >> distance) & 0x1);
    }
    return permutation;
}
// function that returns the low 16 bits of the key, which is given as input in a Hex String format
uint16_t getKeyLow(char* key){
    int i;
    uint16_t keyLow = 0;
    //the least significant 16 bits are the last 4 characters of the key
    for (i=16; i<20; i++)
        //again, multiplication and addition are done using bitwise left shift and bitwise OR
        keyLow = (keyLow << 4) | (((key[i]>='0' && key[i]<='9')? (key[i] - '0') : (key[i] - 'a' + 10)) & 0xF);
    return keyLow;
}
// function that generates subKeys from the key according to the PRESENT key scheduling algorithm for a 80-bit key
uint64_t* generateSubkeys(char* key){
    //the 80 bit key is placed in two integers, one that is 16-bit (keyLow) and the other one is 64-bit (keyHigh)
    uint64_t keyHigh = fromHexStringToLong(key);
    uint16_t keyLow = getKeyLow(key);
    //we allocate space for 32 subkeys, since there are 32 rounds
    uint64_t* subKeys = malloc(32 * (sizeof(uint64_t)));
    int i;
    //the first subkey is the high part of the original key
    subKeys[0] = keyHigh;
    for (i=1; i<32; i++){
        //shifting the whole key (high and low) 61 bits to the left (temporary variables needed to preserve data
        uint64_t temp1 = keyHigh, temp2 = keyLow;
        keyHigh = (keyHigh << 61) | (temp2 << 45) | (temp1 >> 19);
        keyLow = ((temp1 >> 3) & 0xFFFF);
        //the most significant nibble of the key goes through the SBox
        uint8_t temp = Sbox(keyHigh >> 60);
        //the old value of the most significant nibble is set to zero using masking
        keyHigh = keyHigh & 0x0FFFFFFFFFFFFFFFLL;
        //new most significant nibble (output of the SBox) is placed on the most significant location
        keyHigh = keyHigh | (((uint64_t)temp) << 60);
        //key bits on positions k19, k18, k17, k16 and k15 XORed with round counter
        keyLow = keyLow ^ ((i & 0x01) << 15); //k15 is the most significant bit in keyLow
        keyHigh = keyHigh ^ (i >> 1); //the other bits are the least significant ones in keyHigh
        //according to the key scheduling algorithm, the values of keyHigh are used as 64-bit subkeys
        subKeys[i] = keyHigh;
    }
    return subKeys;
}
// function for encrypting a block using a key
char* encrypt(char* plaintext, char* key){
    //generate the subkeys using the function defined above
    uint64_t* subkeys = generateSubkeys(key);
    //convert the plaintext from a Hex String to a 64-bit integer
    uint64_t state = fromHexStringToLong(plaintext);
    int i, j;
    //apply first 31 rounds
    for (i=0; i<31; i++){
        //XOR the state with the round subkey
        state = state ^ subkeys[i];
        //convert the state from a 64-bit integer to an array of bytes (nibbles)
        byte* stateBytes = fromLongToBytes(state);
        //run each nibble through the SBox
        for (j=0; j<8; j++){
            stateBytes[j].nibble1 = Sbox(stateBytes[j].nibble1);
            stateBytes[j].nibble2 = Sbox(stateBytes[j].nibble2);
        }
        //return the nibbles in a 64-bit integer format and perform the permutation defined above
        state = permute(fromBytesToLong(stateBytes));
        //free the memory of the byte array (not needed anymore)
        free(stateBytes);
    }
    //the last round only XORs the state with the round key
    state = state ^ subkeys[31];
    //free the memory of the subkeys (they are not needed anymore)
    free(subkeys);
    return fromLongToHexString(state);
}
// function for decrypting a block using a key
char* decrypt(char* ciphertext, char* key){
    //generate the subkeys using the function defined above
    uint64_t* subkeys = generateSubkeys(key);
    //convert the plaintext from a Hex String to a 64-bit integer
    uint64_t state = fromHexStringToLong(ciphertext);
    int i, j;
    //apply first 31 rounds
    for (i=0; i<31; i++){
        //XOR the state with the round subkey (in decryption, order of subkeys is inversed)
        state = state ^ subkeys[31 - i];
        //perform the inverse permutation defined above
        state = inversepermute(state);
        //convert the state from a 64-bit integer to an array of bytes (nibbles)
        byte* stateBytes = fromLongToBytes(state);
        //run each nibble through the inverse SBox
        for (j=0; j<8; j++){
            stateBytes[j].nibble1 = inverseSbox(stateBytes[j].nibble1);
            stateBytes[j].nibble2 = inverseSbox(stateBytes[j].nibble2);
        }
        //return the nibbles in a 64-bit integer format
        state = fromBytesToLong(stateBytes);
        //free the memory of the byte array (not needed anymore)
        free(stateBytes);
    }
    //the last round only XORs the state with the round key
    state = state ^ subkeys[0];
    //free the memory of the subkeys (they are not needed anymore)
    free(subkeys);
    return fromLongToHexString(state);
}
// main function
int main(){
    //declare a pointer and allocate memory for the plaintext (1 block) and the key
    char *plaintext = malloc(17 * sizeof(char));
    char *key = malloc(21 * sizeof(char));
    //declare a pointer for the ciphertext
    char *ciphertext;
    //code for entering the plaintext and the key
    printf("Enter the plaintext (64 bits) in hexadecimal format\nUse lower case characters and enter new line at the end\n");
    gets(plaintext);
    printf("Enter the key (80 bits) in hexadecimal format\nUse lower case characters and enter new line at the end\n");
    gets(key);
    //calling the encrypt function
    ciphertext = encrypt(plaintext, key);
    //printing the result
    printf("The ciphertext is: ");
    puts(ciphertext);
    printf("The decrypted plaintext is: ");
    //calling the decrypt function and printing the result
    puts(decrypt(ciphertext, key));
    //freeing the allocated memory
    free(key);
    free(plaintext);
    free(ciphertext);
    return 0;
}
