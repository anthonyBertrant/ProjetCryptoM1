import java.io.*;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by anthonybertrant on 06/11/2017.
 * Description: Classe du chiffrement AES
 */
public class AES {

    private int keyLength = 16, Nr = 10, Nk = 4, wideKeyLength = 176;
    private byte[] K = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //clé par defaut
    private byte[] Rcon = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte)0x80, 0x1B, 0x36};
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
    }; //Expension de clé par defaut

    private byte[] resMatrix = new byte[16];
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

    /**
     * Permet de chiffrer le bloc courrant
     */
    public void encryption(){
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

    /**
     * Permet de dechiffrer le bloc courrant
     */
    public void decryption(){
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

    /**
     * Permet d'écrire dans le fichier le bloc dans le fichier désigner
     * @param fos fichier dans le lequel écrire
     * @param blocToWrite bloc à écrire
     */
    private void writer(FileOutputStream fos, byte[] blocToWrite){
        for (int index = 0; index < blocToWrite.length; ++index) {
            try {
                fos.write(blocToWrite[index]);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Permet de chiffer le fichier désigné, avec la clé jointe selon la méthode CBC
     * @param fis nom du fichier d'entrée
     * @param fileName nom du fichier de sortie qui sera généré
     * @param key clé de chiffrement
     */
    public void cbcEncrypt(FileInputStream fis, String fileName, byte[] key){
        //Fonction pour dechiffrement avec une clé
        K = key;        //On affecte la clé de chiffrement
        keyExpansion(); //On appelle keyExpension pour etendre la clé K defini

        try{

            String nameOutput = "pkcs5-" + fileName;
            FileInputStream fichierBourrer = bourrage(fis, nameOutput);
            FileOutputStream fos = new FileOutputStream(new File(fileName));

            randomIV();

            writer(fos, IV);

            byte[] buffer = new byte[16];
            int nbOctetsLus = fichierBourrer.read(buffer);

            while(nbOctetsLus != -1){
                for(int i = 0; i < buffer.length; ++i)
                    state[i] = (byte)(IV[i] ^ buffer[i]);

                encryption();
                System.arraycopy(state, 0, IV, 0, state.length);

                writer(fos, state);
                nbOctetsLus = fichierBourrer.read(buffer);
            }

            fichierBourrer.close();
            fos.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Permet de déchiffer le fichier désigné, avec le clé jointe selon la méthode CBD
     * @param fis nom du fichier chiffré d'entrée
     * @param fileName nom du fichier de sortie qui sera généré
     * @param key clé de déchiffrement
     */
    public void cbcDecrypt(FileInputStream fis, String fileName, byte[] key){

        //Fonction pour dechiffrement avec une clé
        K = key;        //On affecte la clé de chiffrement
        keyExpansion(); //On appelle keyExpension pour etendre la clé K defini

        try{

            FileOutputStream fos = new FileOutputStream(new File(fileName));

            byte[] buffer = new byte[16];

            //recuperation du VI dans le fichier chiffrer
            fis.read(buffer);
            System.arraycopy(buffer, 0, IV, 0, buffer.length);

            int nbOctetsLus = fis.read(buffer);

            while(nbOctetsLus != -1){

                for(int i = 0; i < buffer.length; ++i)
                    state[i] = buffer[i];

                decryption();

                for(int i = 0; i < state.length; ++i)
                    state[i] = (byte)(IV[i] ^ state[i]);

                /*
                 * On applique un traitement spécial pour le dernier bloc
                 * Pour prendre en compte un eventuel padding à supprimer
                 */
                if(fis.available() <= 8){
                    deleteBourage(fos);
                }else{
                    writer(fos, state);
                }
                System.arraycopy(buffer, 0, IV, 0, buffer.length);

                nbOctetsLus = fis.read(buffer);
            }

            fos.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void deleteBourage(FileOutputStream fos) {
        byte lastByte = state[15];
        int nbByteAdd = (int)lastByte;
        boolean flag = true;

        for(int i = 15; i != (16 - nbByteAdd - 1); --i){
            if(state[i] != lastByte){
                flag = false;
                return;
            }
        }

        if(flag){
            //System.arraycopy(state, 0, state, 0, (16 - nbByteAdd-1));
            byte[] tab = Arrays.copyOfRange(state, 0, (16-nbByteAdd));
            writer(fos, tab);
        }else{
            writer(fos, state);
        }
    }

    /**
     * Génère un vecteur d'initialisation de façon aléatoire
     */
    private void randomIV(){
        //Generate a random number between 0 and 255
        //in byte: 0x00 ... 0xFF
        Random randomGenerator = new Random();
        for(int index = 0; index < 16; ++index)
            IV[index] = (byte)randomGenerator.nextInt(256);
    }

    /**
     * Fonction subByte appliquée au bloc courrant
     */
    private void subBytes(){
        int tmp;
        for(int index = 0; index < 16; ++index) {
            tmp = state[index];

            if(tmp < 0)
                tmp = 256 + tmp;

            state[index] = sbox[tmp];
        }
    }

    /**
     * Fonction shiftRows appliquée au bloc courrant
     */
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

    /**
     * Fonction de génération dun fichier bourré pour préparer le chiffrement. Bourrage selon
     * la methode pkcs5
     * @param fis fichier d'entrée
     * @param nameOutput nom du fichier de sortie
     * @return fichier généré
     */
    private FileInputStream bourrage(FileInputStream fis, String nameOutput){

        try {
            FileOutputStream fos = new FileOutputStream(new File(nameOutput));

            long l = fis.getChannel().size();
            long nbOctectToAdd = keyLength - (l % keyLength); //Nombre octect a ajouter pour bourrage
            int valueToAdd = (int)nbOctectToAdd;
            int octet;

            while ((octet = fis.read()) != -1)
                fos.write(octet);

            for (int i = 0; i < nbOctectToAdd; ++i)
                fos.write(valueToAdd);

            return new FileInputStream(new File(nameOutput));

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Renvoie la matrice state courrante
     * @return la matrice state courrante
     */
    public byte[] getState(){
        return state;
    }

    private byte[] rotWord(byte[] tmp){
        byte[] res = new byte[tmp.length];

        res[0] = tmp[1];
        res[1] = tmp[2];
        res[2] = tmp[3];
        res[3] = tmp[0];

        return res;
    }

    private byte[] subWord(byte[] tmp){
        byte[] res = new byte[tmp.length];

        if(tmp[0] < 0)
            res[0] = sbox[tmp[0] + 256];
        else
            res[0] = sbox[tmp[0]];

        if(tmp[1] < 0)
            res[1] = sbox[tmp[1] + 256];
        else
            res[1] = sbox[tmp[1]];


        if(tmp[2] < 0)
            res[2] = sbox[tmp[2] + 256];

        else
            res[2] = sbox[tmp[2]];


        if(tmp[3] < 0)
            res[3] = sbox[tmp[3] + 256];
        else
            res[3] = sbox[tmp[3]];


        return res;
    }

    private void keyExpansion(){
        byte[] tmp = new byte[4];
        byte[] w1 = new byte[256];

        for(int i = 0; i < K.length; ++i)
            w1[i] = K[i];


        for(int i = Nk; i < (4*(Nr + 1) -1); ++i){

            //Met dans tmp la colonne Nk - 1
            for(int index = 0; index < 4; ++index)
                tmp[index] = w1[i + index - 1];

            if( (i % Nk) == 0){
                tmp = rotWord(tmp);
                tmp = subWord(tmp);

                for (int index = 0; index < tmp.length; ++index)
                    tmp[index] = gmul(tmp[index], Rcon[i/Nk-1]);

            }else if( (Nk > 6) && ((i % Nk) == 4)){
                tmp = subWord(tmp);
            }

            for(int index = 0; index < tmp.length; ++index)
                tmp[index] = gmul(w1[index + (i - Nk)], tmp[index]);

            for(int index = 0; index < tmp.length; ++index)
                w1[(Nk + i) + index] = tmp[index];
        }

        W = w1;
    }

    /**
     * Affichage sous forme hexadécimal d'une suite d'octets
     * @param donnees
     * @return chaine hexa
     */
    public static String toHex(byte[] donnees) {
        return "0x" + javax.xml.bind.DatatypeConverter.printHexBinary(donnees);
    }

}
