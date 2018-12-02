package WSCommonLib;

/**
 *
 * 
 */

import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Base64;
import javax.xml.bind.annotation.*;
import java.time.Clock;
//import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
//import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Random;

@XmlType(namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
public class UsernameTokenType {
    public static int created_maxMoreSeconds = 600;
    public static int created_maxLessSeconds = 600;
    public static int maxBadPasswords_timeoutSeconds = 3 * 60;
    @XmlElement(name = "Username", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", required = true)
    public String username;
    @XmlElement(name = "Password", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", required = true)
    public String password;
    @XmlElement(name = "Nonce", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", required = true)
    public String nonce;
    @XmlElement(name = "Created", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", required = true)
    public String created;
    @XmlElement(name = "TempLockId")
    public String tempLockId;
    
    OffsetDateTime getCreated_OffsetDateTime() throws PasswordValidationException
    {
        String errmsg = "формат (yyyy-MM-ddTHH:mm:ssZ или yyyy-MM-ddTHH:mm:ss.SSSZ или yyyy-MM-ddTHH:mmZ) тега Created (" + created + ") не соблюдён";
        try
        {
            new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").parse(created);//проверка
        }
        catch(ParseException ex)
        {
            try
            {
                new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").parse(created);//проверка
            }
            catch(ParseException ex2)
            {
                try
                {
                    new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'").parse(created);//проверка
                }
                catch(ParseException ex3)
                {
                    throw new PasswordValidationException(errmsg + ".");
                }
            }
        }
        try
        {
            return OffsetDateTime.parse(created);     
        }
        catch(DateTimeParseException ex)
        {
            throw new PasswordValidationException(errmsg + ": " + ex.getMessage());
        }   
    }
    static class userLastLoginType {
        public long loginTryTimeStamp;
        public int badPasswords;
        //public long goodCreated_sec;
        //public String goodNonce;
        @SuppressWarnings("unchecked")
        HashMap<String, Object>[] goodNonces = new HashMap[] { new HashMap<>(), new HashMap<>() };
        long goodNonces_lastswapZ_sec; 
        int  goodNonces_active; 
        public synchronized void checkNonce(String value) throws PasswordValidationException, RetryAuthenticationException
        {
            Long nowZ_sec = Clock.systemUTC().millis()/1000;  
            if (goodNonces_lastswapZ_sec == 0)
                goodNonces_lastswapZ_sec = nowZ_sec;
            if (goodNonces_lastswapZ_sec + created_maxLessSeconds < nowZ_sec)
            {
                goodNonces_active++;
                if (goodNonces.length >= goodNonces_active)
                    goodNonces_active = 0;
                goodNonces[goodNonces_active] = new HashMap<>();
                goodNonces_lastswapZ_sec = nowZ_sec;
            }
            for (HashMap<String, Object> goodNonce : goodNonces)
                if (goodNonce.containsKey(value))
                    throw new RetryAuthenticationException("Обнаружена попытка повторного использования значения тега Nonce!"); 
            goodNonces[goodNonces_active].put(value, new Object());
        }
    }
    static HashMap<String, userLastLoginType> userLastLogins = new HashMap<>();
    static final Object userLastLoginsLOCK = new Object();
    userLastLoginType UserLastLogin()
    {
        if (!userLastLogins.containsKey(username.toLowerCase()))
        {
            synchronized(userLastLoginsLOCK)
            {
                if (!userLastLogins.containsKey(username.toLowerCase()))
                {
                    userLastLogins.put(username.toLowerCase(), new userLastLoginType());
                }                
            }
        }
        return userLastLogins.get(username.toLowerCase());
    }
    public boolean checkPwd(String GoodPwd) throws PasswordValidationException, RetryAuthenticationException
    {
        userLastLoginType ull = UserLastLogin();
        long now = new Date().getTime();
        try
        {
            if (ull.badPasswords >= 8)
            {
                if (maxBadPasswords_timeoutSeconds > 0 && (ull.loginTryTimeStamp + (maxBadPasswords_timeoutSeconds * 1000)) > now)
                {//блокировка на maxBadPasswords_timeoutSeconds
                    throw new PasswordValidationException("Превышено количество неудачных попыток входа!");
                }
                else
                {
                    ull.badPasswords = 0;
                }
            }
            if (created == null || created.isEmpty())
                throw new PasswordValidationException("Поле Created должно быть заполнено!");
            if (nonce == null || nonce.isEmpty())
                throw new PasswordValidationException("Поле Nonce должно быть заполнено!");
            if (password == null || password.isEmpty())
                throw new PasswordValidationException("Поле Password должно быть заполнено!");
                
            Long nowZ_sec = Clock.systemUTC().millis()/1000;        
            Long Created_sec = getCreated_OffsetDateTime().toEpochSecond();
            if(Created_sec > nowZ_sec + created_maxMoreSeconds)
                throw new PasswordValidationException("Указанная метка времени (" + created + ") больше времени сервера (" + OffsetDateTime.now(Clock.systemUTC()).truncatedTo(ChronoUnit.SECONDS).toString() + ") более чем на допустимые " + Integer.toString(created_maxMoreSeconds) + " секунд (указано время в UTC).");
            if(Created_sec < nowZ_sec - created_maxLessSeconds)
                throw new PasswordValidationException("Указанная метка времени (" + created + ") меньше времени сервера (" + OffsetDateTime.now(Clock.systemUTC()).truncatedTo(ChronoUnit.SECONDS).toString() + ") более чем на допустимые " + Integer.toString(created_maxLessSeconds) + " секунд (указано время в UTC).");

            String GoodPwdDig = getPwdDig(nonce, created, GoodPwd);

            boolean result = GoodPwdDig.equals(password);
            if (result)
            {
                ull.checkNonce(nonce);
                ull.badPasswords = 0;
            }
            else
            {
                ull.badPasswords++;
            }            

            return result;
        }
        finally
        {
            ull.loginTryTimeStamp = now;
        }
    }
    public static UsernameTokenType get(String Username, String Pwd)
    {
        UsernameTokenType result = new UsernameTokenType();
        result.username = Username;
        result.created = OffsetDateTime.now(Clock.systemUTC()).toString();
        Random rnd = new Random();        
        result.nonce = Base64.getEncoder().encodeToString(((new Long(rnd.nextLong())).toString() + (new Long(rnd.nextLong())).toString()).getBytes());
        try {
            result.password = getPwdDig(result.nonce, result.created, Pwd);
        } catch (PasswordValidationException ex) {
            throw new RuntimeException(ex);
        }
        return result;
    }
    static String getPwdDig(String Nonce, String Created, String Pwd) throws PasswordValidationException
    {
        byte[] NonceB;
        try
        {
            NonceB = Base64.getDecoder().decode(Nonce); 
        }
        catch(Exception ex)
        {
            throw new PasswordValidationException("формат (BASE64) тега Nonce (" + Nonce + ") не соблюдён.");
        }
        if (NonceB.length > 64)
            throw new PasswordValidationException("длина тега Nonce не может превышать 64 байта!");
        try{
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            byte[]  CreatedB = Created.getBytes("UTF8");
            byte[]  GoodPwdB = Pwd.getBytes("UTF8");
            byte[] ncpB = new byte[NonceB.length + CreatedB.length + GoodPwdB.length];
            System.arraycopy(NonceB, 0, ncpB, 0, NonceB.length);
            System.arraycopy(CreatedB, 0, ncpB, NonceB.length, CreatedB.length);
            System.arraycopy(GoodPwdB, 0, ncpB, NonceB.length + CreatedB.length, GoodPwdB.length);
            return Base64.getEncoder().encodeToString(sha1.digest(ncpB));
        }catch(Exception ex){throw new PasswordValidationException(ex);}
    }
        
    public static class PasswordValidationException extends Exception {
        @XmlTransient
        public String internalDetails;
        public PasswordValidationException(String message) {
            super(message);
        }
        public PasswordValidationException(String message, String internalDetails) {
            super(message);
            this.internalDetails = internalDetails;
        }
        public PasswordValidationException(Throwable ex) {
            super(ex);
        }
    }
    public static class RetryAuthenticationException extends Exception {
        public RetryAuthenticationException(String message) {
            super(message);
        }
    }
}
