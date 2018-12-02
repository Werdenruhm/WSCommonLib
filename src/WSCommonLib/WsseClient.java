package WSCommonLib;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.Random;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 *
 * 
 */
public class WsseClient {
    @FunctionalInterface
    public interface CommonSecuredWsMethod<Treq, Tresp, Tsecurity>
    {
        Tresp call(Treq req, Tsecurity security) throws Exception;
    }
    public static <Treq, Tresp, Tsecurity> Tresp callSecuredWsMethod(
        CommonSecuredWsMethod<Treq, Tresp, Tsecurity> securedWsMethod, Treq req, Supplier<Tsecurity> getSec, Class<? extends Exception> cls_retryException)         
    {
        return callSecuredWsMethod(securedWsMethod, req, getSec, cls_retryException, RuntimeException.class, RuntimeException.class, RuntimeException.class);
    }
    public static <Treq, Tresp, Tsecurity, E1 extends Exception> Tresp callSecuredWsMethod(
        CommonSecuredWsMethod<Treq, Tresp, Tsecurity> securedWsMethod, Treq req, Supplier<Tsecurity> getSec, Class<? extends Exception> cls_retryException, Class<E1> cls_E1)
        throws E1
    {
        return callSecuredWsMethod(securedWsMethod, req, getSec, cls_retryException, cls_E1, RuntimeException.class, RuntimeException.class);
    }
    public static <Treq, Tresp, Tsecurity, E1 extends Exception, E2 extends Exception> Tresp callSecuredWsMethod(
        CommonSecuredWsMethod<Treq, Tresp, Tsecurity> securedWsMethod, Treq req, Supplier<Tsecurity> getSec, Class<? extends Exception> cls_retryException, Class<E1> cls_E1, Class<E2> cls_E2)
        throws E1, E2
    {
        return callSecuredWsMethod(securedWsMethod, req, getSec, cls_retryException, cls_E1, cls_E2, RuntimeException.class);
    }
    @SuppressWarnings("unchecked")
    public static <Treq, Tresp, Tsecurity, E1 extends Exception, E2 extends Exception, E3 extends Exception> Tresp callSecuredWsMethod(
        CommonSecuredWsMethod<Treq, Tresp, Tsecurity> securedWsMethod, Treq req, Supplier<Tsecurity> getSec, Class<? extends Exception> cls_retryException, Class<E1> cls_E1, Class<E2> cls_E2, Class<E3> cls_E3)
        throws E1, E2, E3
    {
        for(int trys = 1; true; trys++)
        {
            try 
            {
                return securedWsMethod.call(req, getSec.get());
            } 
            catch (Exception ex) 
            {                    
                if (cls_retryException != null && cls_retryException.isAssignableFrom(ex.getClass()))  
                {
                    if (trys >= 3)
                        throw new RuntimeException(ex);
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException iex) {
                        throw new RuntimeException(iex);
                    }
                }
                else if (cls_E1 != null && cls_E1.isAssignableFrom(ex.getClass()))
                    throw (E1)ex;
                else if (cls_E2 != null && cls_E2.isAssignableFrom(ex.getClass()))
                    throw (E2)ex;            
                else if (cls_E3 != null && cls_E3.isAssignableFrom(ex.getClass()))
                    throw (E3)ex;            
                else if (ex instanceof RuntimeException)
                    throw (RuntimeException)ex;            
                else
                    throw new RuntimeException(ex);
            }
        }
    }
    
    public static String getSHA1HexHash(String value)
    {
        return bytesToHex(getSHA1(value));
    }
    public static byte[] getSHA1(String value)
    {
        return SHA1().digest(value.getBytes(StandardCharsets.UTF_8));
    }
    public static MessageDigest SHA1()
    {        
        try {
            return MessageDigest.getInstance("SHA1");
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
    final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static void setUsernameTokenFields(String Pwd, Consumer<String> createdSetter, Consumer<String> nonceSetter, Consumer<String> passwordSetter)
    {
        Random rnd = new Random();        
        String created = OffsetDateTime.now(Clock.systemUTC()).toString();
        String nonce = Base64.getEncoder().encodeToString(((new Long(rnd.nextLong())).toString() + (new Long(rnd.nextLong())).toString()).getBytes());
        String password = getPwdDig(nonce, created, Pwd);
        createdSetter.accept(created);
        nonceSetter.accept(nonce);
        passwordSetter.accept(password);
    }
    public static String getPwdDig(String Nonce, String Created, String Pwd) 
    {
        byte[] NonceB;
        try
        {
            NonceB = Base64.getDecoder().decode(Nonce); 
        }
        catch(Exception ex)
        {
            throw new RuntimeException("формат (BASE64) тега Nonce (" + Nonce + ") не соблюдён.");
        }
        if (NonceB.length > 64)
            throw new RuntimeException("длина тега Nonce не может превышать 64 байта!");

        byte[]  CreatedB;
        byte[]  GoodPwdB;
        CreatedB = Created.getBytes(StandardCharsets.UTF_8);
        GoodPwdB = Pwd.getBytes(StandardCharsets.UTF_8);
        byte[] ncpB = new byte[NonceB.length + CreatedB.length + GoodPwdB.length];
        System.arraycopy(NonceB, 0, ncpB, 0, NonceB.length);
        System.arraycopy(CreatedB, 0, ncpB, NonceB.length, CreatedB.length);
        System.arraycopy(GoodPwdB, 0, ncpB, NonceB.length + CreatedB.length, GoodPwdB.length);
        return Base64.getEncoder().encodeToString(SHA1().digest(ncpB));
    }
}
