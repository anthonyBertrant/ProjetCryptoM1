import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by anthonybertrant on 14/11/2017.
 * Description:
 */
public class MD5 {

    public byte[] generateMD5(String input){
        byte[] buffer = input.getBytes();
        try {
            MessageDigest hachage = MessageDigest.getInstance("MD5");

            hachage.update(buffer, 0, buffer.length);

            return hachage.digest();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
