import java.io.*;
import java.util.Random;

/**
 * Created by anthonybertrant on 06/11/2017.
 * Description: Classe du chiffrement AES
 */
public class AES {

    private int keyLength = 16, Nr = 10, Nk = 4, wideKeyLength = 176;
    private byte[] K = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] W = {
            (byte) 0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte) 0x62, (byte)0x63, (byte)0x63, (byte)0x63, (byte)0x62, (byte)0x63, (byte)0x63, (byte)0x63, (byte)0x62, (byte)0x63, (byte)0x63, (byte)0x63, (byte)0x62, (byte)0x63, (byte)0x63, (byte)0x63,
            (byte) 0x9B, (byte)0x98, (byte)0x98, (byte)0xC9, (byte)0xF9, (byte)0xFB, (byte)0xFB, (byte)0xAA, (byte)0x9B, (byte)0x98, (byte)0x98, (byte)0xC9, (byte)0xF9, (byte)0xFB, (byte)0xFB, (byte)0xAA,
            (byte) 0x90, (byte)0x97, (byte)0x34, (byte)0x50, (byte)0x69, (byte)0x6C, (byte)0xCF, (byte)0xFA, (byte)0xF2, (byte)0xF4, (byte)0x57, (byte)0x33, (byte)0x0B, (byte)0x0F, (byte)0xAC, (byte)0x99,
            (byte) 0xEE, (byte)0x06, (byte)0xDA, (byte)0x7B, (byte)0x87, (byte)0x6A, (byte)0x15, (byte)0x81, (byte)0x75, (byte)0x9E, (byte)0x42, (byte)0xB2, (byte)0x7E, (byte)0x91, (byte)0xEE, (byte)0x2B,
            (byte) 0x7F, (byte)0x2E, (byte)0x2B, (byte)0x88, (byte)0xF8, (byte)0x44, (byte)0x3E, (byte)0x09, (byte)0x8D, (byte)0xDA, (byte)0x7C, (byte)0xBB, (byte)0xF3, (byte)0x4B, (byte)0x92, (byte)0x90,
            (byte) 0xEC, (byte)0x61, (byte)0x4B, (byte)0x85, (byte)0x14, (byte)0x25, (byte)0x75, (byte)0x8C, (byte)0x99, (byte)0xFF, (byte)0x09, (byte)0x37, (byte)0x6A, (byte)0xB4, (byte)0x9B, (byte)0xA7,
            (byte) 0x21, (byte)0x75, (byte)0x17, (byte)0x87, (byte)0x35, (byte)0x50, (byte)0x62, (byte)0x0B, (byte)0xAC, (byte)0xAF, (byte)0x6B, (byte)0x3C, (byte)0xC6, (byte)0x1B, (byte)0xF0, (byte)0x9B,
            (byte) 0x0E, (byte)0xF9, (byte)0x03, (byte)0x33, (byte)0x3B, (byte)0xA9, (byte)0x61, (byte)0x38, (byte)0x97, (byte)0x06, (byte)0x0A, (byte)0x04, (byte)0x51, (byte)0x1D, (byte)0xFA, (byte)0x9F,
            (byte) 0xB1, (byte)0xD4, (byte)0xD8, (byte)0xE2, (byte)0x8A, (byte)0x7D, (byte)0xB9, (byte)0xDA, (byte)0x1D, (byte)0x7B, (byte)0xB3, (byte)0xDE, (byte)0x4C, (byte)0x66, (byte)0x49, (byte)0x41,
            (byte) 0xB4, (byte)0xEF, (byte)0x5B, (byte)0xCB, (byte)0x3E, (byte)0x92, (byte)0xE2, (byte)0x11, (byte)0x23, (byte)0xE9, (byte)0x51, (byte)0xCF, (byte)0x6F, (byte)0x8F, (byte)0x18, (byte)0x8E
    };

    private byte[] resMatrix= new byte[16], blocsRead = new byte[16], blocsCrypt = new byte[16];
    private byte[] matrix = {0x02, 0x01, 0x01, 0x03 ,0x03, 0x02, 0x01, 0x01, 0x01, 0x03, 0x02, 0x01, 0x01, 0x01, 0x03, 0x02};
    private byte[] IV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] state = {0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    private byte[] sbox = {
         (byte)0x63,  (byte)0x7C,  (byte)0x77,  (byte)0x7B,  (byte)0xF2,  (byte)0x6B,  (byte)0x6F,  (byte)0xC5,  (byte)0x30,  (byte)0x01,  (byte)0x67,  (byte)0x2B,  (byte)0xFE,  (byte)0xD7,  (byte)0xAB,  (byte)0x76,
         (byte)0xCA,  (byte)0x82,  (byte)0xC9,  (byte)0x7D,  (byte)0xFA,  (byte)0x59,  (byte)0x47,  (byte)0xF0,  (byte)0xAD,  (byte)0xD4,  (byte)0xA2,  (byte)0xAF,  (byte)0x9C,  (byte)0xA4,  (byte)0x72,  (byte)0xC0,
         (byte)0xB7,  (byte)0xFD,  (byte)0x93,  (byte)0x26,  (byte)0x36,  (byte)0x3F,  (byte)0xF7,  (byte)0xCC,  (byte)0x34,  (byte)0xA5,  (byte)0xE5,  (byte)0xF1,  (byte)0x71,  (byte)0xD8,  (byte)0x31,  (byte)0x15,
         (byte)0x04,  (byte)0xC7,  (byte)0x23,  (byte)0xC3,  (byte)0x18,  (byte)0x96,  (byte)0x05,  (byte)0x9A,  (byte)0x07,  (byte)0x12,  (byte)0x80,  (byte)0xE2,  (byte)0xEB,  (byte)0x27,  (byte)0xB2,  (byte)0x75,
         (byte)0x09,  (byte)0x83,  (byte)0x2C,  (byte)0x1A,  (byte)0x1B,  (byte)0x6E,  (byte)0x5A,  (byte)0xA0,  (byte)0x52,  (byte)0x3B,  (byte)0xD6,  (byte)0xB3,  (byte)0x29,  (byte)0xE3,  (byte)0x2F,  (byte)0x84,
         (byte)0x53,  (byte)0xD1,  (byte)0x00,  (byte)0xED,  (byte)0x20,  (byte)0xFC,  (byte)0xB1,  (byte)0x5B,  (byte)0x6A,  (byte)0xCB,  (byte)0xBE,  (byte)0x39,  (byte)0x4A,  (byte)0x4C,  (byte)0x58,  (byte)0xCF,
         (byte)0xD0,  (byte)0xEF,  (byte)0xAA,  (byte)0xFB,  (byte)0x43,  (byte)0x4D,  (byte)0x33,  (byte)0x85,  (byte)0x45,  (byte)0xF9,  (byte)0x02,  (byte)0x7F,  (byte)0x50,  (byte)0x3C,  (byte)0x9F,  (byte)0xA8,
         (byte)0x51,  (byte)0xA3,  (byte)0x40,  (byte)0x8F,  (byte)0x92,  (byte)0x9D,  (byte)0x38,  (byte)0xF5,  (byte)0xBC,  (byte)0xB6,  (byte)0xDA,  (byte)0x21,  (byte)0x10,  (byte)0xFF,  (byte)0xF3,  (byte)0xD2,
         (byte)0xCD,  (byte)0x0C,  (byte)0x13,  (byte)0xEC,  (byte)0x5F,  (byte)0x97,  (byte)0x44,  (byte)0x17,  (byte)0xC4,  (byte)0xA7,  (byte)0x7E,  (byte)0x3D,  (byte)0x64,  (byte)0x5D,  (byte)0x19,  (byte)0x73,
         (byte)0x60,  (byte)0x81,  (byte)0x4F,  (byte)0xDC,  (byte)0x22,  (byte)0x2A,  (byte)0x90,  (byte)0x88,  (byte)0x46,  (byte)0xEE,  (byte)0xB8,  (byte)0x14,  (byte)0xDE,  (byte)0x5E,  (byte)0x0B,  (byte)0xDB,
         (byte)0xE0,  (byte)0x32,  (byte)0x3A,  (byte)0x0A,  (byte)0x49,  (byte)0x06,  (byte)0x24,  (byte)0x5C,  (byte)0xC2,  (byte)0xD3,  (byte)0xAC,  (byte)0x62,  (byte)0x91,  (byte)0x95,  (byte)0xE4,  (byte)0x79,
         (byte)0xE7,  (byte)0xC8,  (byte)0x37,  (byte)0x6D,  (byte)0x8D,  (byte)0xD5,  (byte)0x4E,  (byte)0xA9,  (byte)0x6C,  (byte)0x56,  (byte)0xF4,  (byte)0xEA,  (byte)0x65,  (byte)0x7A,  (byte)0xAE,  (byte)0x08,
         (byte)0xBA,  (byte)0x78,  (byte)0x25,  (byte)0x2E,  (byte)0x1C,  (byte)0xA6,  (byte)0xB4,  (byte)0xC6,  (byte)0xE8,  (byte)0xDD,  (byte)0x74,  (byte)0x1F,  (byte)0x4B,  (byte)0xBD,  (byte)0x8B,  (byte)0x8A,
         (byte)0x70,  (byte)0x3E,  (byte)0xB5,  (byte)0x66,  (byte)0x48,  (byte)0x03,  (byte)0xF6,  (byte)0x0E,  (byte)0x61,  (byte)0x35,  (byte)0x57,  (byte)0xB9,  (byte)0x86,  (byte)0xC1,  (byte)0x1D,  (byte)0x9E,
         (byte)0xE1,  (byte)0xF8,  (byte)0x98,  (byte)0x11,  (byte)0x69,  (byte)0xD9,  (byte)0x8E,  (byte)0x94,  (byte)0x9B,  (byte)0x1E,  (byte)0x87,  (byte)0xE9,  (byte)0xCE,  (byte)0x55,  (byte)0x28,  (byte)0xDF,
         (byte)0x8C,  (byte)0xA1,  (byte)0x89,  (byte)0x0D,  (byte)0xBF,  (byte)0xE6,  (byte)0x42,  (byte)0x68,  (byte)0x41,  (byte)0x99,  (byte)0x2D,  (byte)0x0F,  (byte)0xB0,  (byte)0x54,  (byte)0xBB,  (byte)0x16
    };
    private byte[] sboxInv = {
            (byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38, (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E, (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB,
            (byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87, (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44, (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB,
            (byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2, (byte) 0x23, (byte) 0x3D, (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B, (byte) 0x42, (byte) 0xFA, (byte) 0xC3, (byte) 0x4E,
            (byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9, (byte) 0x24, (byte) 0xB2, (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49, (byte) 0x6D, (byte) 0x8B, (byte) 0xD1, (byte) 0x25,
            (byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC, (byte) 0x5D, (byte) 0x65, (byte) 0xB6, (byte) 0x92,
            (byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA, (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84,
            (byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC, (byte) 0xD3, (byte) 0x0A, (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05, (byte) 0xB8, (byte) 0xB3, (byte) 0x45, (byte) 0x06,
            (byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F, (byte) 0x0F, (byte) 0x02, (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8A, (byte) 0x6B,
            (byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67, (byte) 0xDC, (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE, (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, (byte) 0x73,
            (byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD, (byte) 0x35, (byte) 0x85, (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8, (byte) 0x1C, (byte) 0x75, (byte) 0xDF, (byte) 0x6E,
            (byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29, (byte) 0xC5, (byte) 0x89, (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E, (byte) 0xAA, (byte) 0x18, (byte) 0xBE, (byte) 0x1B,
            (byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2, (byte) 0x79, (byte) 0x20, (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, (byte) 0x78, (byte) 0xCD, (byte) 0x5A, (byte) 0xF4,
            (byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xC7, (byte) 0x31, (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xEC, (byte) 0x5F,
            (byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5, (byte) 0x4A, (byte) 0x0D, (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F, (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF,
            (byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A, (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61,
            (byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77, (byte) 0xD6, (byte) 0x26, (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0C, (byte) 0x7D
    };

    private void encryption(){
        int round;
        addRoundKey(0);
        for (round = 1; round < Nr; ++round) {
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(round);
        }
        subBytes();
        shiftRows();
        addRoundKey(Nr);
    }

    private void decryption(){
        int round;
        addRoundKey(Nr);
        for (round = (Nr - 1); round > 0; --round) {
            invShiftRows();
            invSubBytes();
            addRoundKey(round);
            invMixColumns();
        }
        invShiftRows();
        invSubBytes();
        addRoundKey(0);
    }

    private void writer(FileOutputStream fos, byte[] blocToWrite){
        for (int index = 0; index < blocToWrite.length; ++index) {
            try {
                fos.write(blocToWrite[index]);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void cbcEncrypt(FileInputStream fis, String fileName){
        try{

            FileInputStream fichierBourrer = bourrage(fis);
            FileOutputStream fos = new FileOutputStream(new File(fileName));

            randomIV();
            writer(fos, IV);

            int actualByte;
            for(int index = 0; index < 16; ++index){
                blocsRead[index] = (byte)fichierBourrer.read();
            }

            for(int index = 0; index < 16; ++index)
                state[index] = (byte) (IV[index] ^ blocsRead[index]);

            encryption();

            writer(fos, state);

            System.arraycopy(state, 0, IV, 0, state.length);


            int index = 0;
            int loop = 1;

            while ((actualByte = fichierBourrer.read()) != -1){

                if(index == 16) {

                    encryption();

                    System.arraycopy(state, 0, IV, 0, state.length);

                    writer(fos, state);
                    System.out.println("bloc n°" + loop + " traité");
                    ++loop;
                    index = 0;
                }
                blocsRead[index] = (byte)actualByte;
                state[index] = (byte)(IV[index] ^ blocsRead[index]);

                ++index;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String toHex(byte[] donnees) {
        return "0x" + javax.xml.bind.DatatypeConverter.printHexBinary(donnees);
    }

    public void cbcDecrypt(FileInputStream fis, String fileName){
        try{

            FileOutputStream fos = new FileOutputStream(new File(fileName));

            setIvFromEncrypt(fis);

            int actualByte;
            for(int i = 0; i < 16; ++i){
                blocsCrypt[i] = (byte)fis.read();
                state[i] = blocsCrypt[i];
            }

            decryption();

            for(int index = 0; index < 16; ++index)
                state[index] = (byte) (IV[index] ^ state[index]);

            writer(fos, state); //Bloc totalement déchiffer et clair

            System.arraycopy(blocsCrypt, 0, IV, 0, blocsCrypt.length); //IV est le bloc chiffré, précedent lu

            int index = 0;
            int loop = 1;
            while ((actualByte = fis.read()) != -1){

                if(index == 16){

                    decryption();

                    for (int i = 0; i < 16; ++i)
                        state[i] = (byte)(IV[i] ^ state[i]);

                    writer(fos, state);
                    System.out.println("bloc n°" + loop + " traité");
                    ++loop;

                    System.arraycopy(blocsCrypt, 0, IV, 0, blocsCrypt.length);
                    index = 0;
                }
                blocsCrypt[index] = (byte)actualByte;
                state[index] = blocsCrypt[index];
                ++index;
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void randomIV(){
        //Generate a random number between 0 and 255
        //in byte: 0x00 ... 0xFF
        Random randomGenerator = new Random();
        for(int index = 0; index < 16; ++index)
            IV[index] = (byte)randomGenerator.nextInt(256);
    }

    private void setIvFromEncrypt(FileInputStream fis){
        try{

            for(int i = 0; i < 16; ++i){
                IV[i] = (byte)fis.read();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void subBytes(){
        int tmp;
        for(int index = 0; index < 16; ++index) {
            tmp = state[index];

            if(tmp < 0)
                tmp = 256 + tmp;

            state[index] = sbox[tmp];
        }
    }

    private void shiftRows(){
        byte[] state2 = new byte[16];
        for(int i = 0; i < 16; ++i)
            state2[i] = state[i];

        state[1]  = state2[5];
        state[5]  = state2[9];
        state[9]  = state2[13];
        state[13] = state2[1];

        state[2]  = state2[10];
        state[6]  = state2[14];
        state[10] = state2[2];
        state[14] = state2[6];

        state[3]  = state2[15];
        state[7]  = state2[3];
        state[11] = state2[7];
        state[15] = state2[11];
    }

    private void mixColumns(){
        prodMatrix(state[0],state[1], state[2], state[3]);
        for (int i = 0; i < 4; ++i) {
            state[i] = resMatrix[i];
        }
        prodMatrix(state[4],state[5], state[6], state[7]);
        for (int i = 0; i < 4; ++i) {
            state[i+4] = resMatrix[i];
        }

        prodMatrix(state[8],state[9], state[10], state[11]);
        for (int i = 0; i < 4; ++i) {
            state[i+8] = resMatrix[i];
        }

        prodMatrix(state[12],state[13], state[14], state[15]);
        for (int i = 0; i < 4; ++i) {
            state[i+12] = resMatrix[i];
        }
    }

    private void prodMatrix(byte a0, byte a1, byte a2, byte a3){
        resMatrix[0] = (byte) (gmul(matrix[0], a0) ^ gmul(matrix[4], a1) ^ gmul(matrix[8], a2) ^  gmul(matrix[12], a3));
        resMatrix[1] = (byte) (gmul(matrix[1], a0) ^ gmul(matrix[5], a1) ^ gmul(matrix[9], a2) ^  gmul(matrix[13], a3));
        resMatrix[2] = (byte) (gmul(matrix[2], a0) ^ gmul(matrix[6], a1) ^ gmul(matrix[10], a2) ^ gmul(matrix[14], a3));
        resMatrix[3] = (byte) (gmul(matrix[3], a0) ^ gmul(matrix[7], a1) ^ gmul(matrix[11], a2) ^ gmul(matrix[15], a3));
    }

    private void prodMatrixInv(byte a0, byte a1, byte a2, byte a3){
        resMatrix[0] = (byte) (gmul(state[0], a0) ^ gmul(state[4], a1) ^ gmul(state[8],  a2) ^ gmul(state[12], a3));
        resMatrix[1] = (byte) (gmul(state[1], a0) ^ gmul(state[5], a1) ^ gmul(state[9],  a2) ^ gmul(state[13], a3));
        resMatrix[2] = (byte) (gmul(state[2], a0) ^ gmul(state[6], a1) ^ gmul(state[10], a2) ^ gmul(state[14], a3));
        resMatrix[3] = (byte) (gmul(state[3], a0) ^ gmul(state[7], a1) ^ gmul(state[11], a2) ^ gmul(state[15], a3));

        resMatrix[0] = (byte) (gmul((byte)0x0E, a0) ^ gmul((byte)0x0B, a1) ^ gmul((byte)0x0D, a2) ^ gmul((byte)0x09, a3));
        resMatrix[1] = (byte) (gmul((byte)0x09, a0) ^ gmul((byte)0x0E, a1) ^ gmul((byte)0x0B, a2) ^ gmul((byte)0x0D, a3));
        resMatrix[2] = (byte) (gmul((byte)0x0D, a0) ^ gmul((byte)0x09, a1) ^ gmul((byte)0x0E, a2) ^ gmul((byte)0x0B, a3));
        resMatrix[3] = (byte) (gmul((byte)0x0B, a0) ^ gmul((byte)0x0D, a1) ^ gmul((byte)0x09, a2) ^ gmul((byte)0x0E, a3));
    }

    private void addRoundKey(int r){
        for(int index = 0; index < 16; ++index)
            state[index] = (byte) (state[index] ^ W[index + (16*r)]);
    }

    private void invSubBytes(){
        int tmp;
        for(int index = 0; index < 16; ++index){
            tmp = state[index];

            if(tmp < 0)
                tmp = 256 + tmp;
            state[index] = sboxInv[tmp];
        }
    }

    private void invMixColumns(){
        prodMatrixInv(state[0],state[1], state[2], state[3]);
        for (int i = 0; i < 4; ++i) {
            state[i] = resMatrix[i];
        }

        prodMatrixInv(state[4],state[5], state[6], state[7]);
        for (int i = 0; i < 4; ++i) {
            state[i+4] = resMatrix[i];
        }

        prodMatrixInv(state[8],state[9], state[10], state[11]);
        for (int i = 0; i < 4; ++i) {
            state[i+8] = resMatrix[i];
        }

        prodMatrixInv(state[12],state[13], state[14], state[15]);
        for (int i = 0; i < 4; ++i) {
            state[i+12] = resMatrix[i];
        }
    }

    private void invShiftRows(){
        byte[] state2 = new byte[16];
        for(int i = 0; i < 16; ++i)
            state2[i] = state[i];

        state[1]  = state2[13];
        state[5]  = state2[1];
        state[9]  = state2[5];
        state[13] = state2[9];

        state[2]  = state2[10];
        state[6]  = state2[14];
        state[10] = state2[2];
        state[14] = state2[6];

        state[3]  = state2[7];
        state[7]  = state2[11];
        state[11] = state2[15];
        state[15] = state2[3];
    }

    private byte gmul(byte a, byte b){
        byte p = 0;
        byte hi_bit_set;

        for (int i = 0; i < 8; ++i){
            if((b & 1) == 1)
                p ^= a;
            hi_bit_set = (byte)(a & 0x80);
            a <<= 1;
            if(hi_bit_set == (byte)0x80)
                a ^= (byte)0x1b;
            b >>= 1;
        }
        return p;
    }

    private FileInputStream bourrage(FileInputStream fis){
        int k = 16; //Taille des blocs de l'AES

        try {
            FileOutputStream fos = new FileOutputStream(new File("src/main/java/pkcs5-butokuden.jpg"));

            long l = fis.getChannel().size();
            long nbOctectToAdd = k - (l % k); //Nombre octect a ajouter pour bourrage
            int valueToAdd = (int)nbOctectToAdd;
            int octet;

            while ((octet = fis.read()) != -1)
                fos.write(octet);

            for (int i = 0; i < nbOctectToAdd; ++i)
                fos.write(valueToAdd);

            return new FileInputStream(new File("src/main/java/pkcs5-butokuden.jpg"));

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

}
