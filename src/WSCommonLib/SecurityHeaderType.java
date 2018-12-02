package WSCommonLib;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.w3c.dom.Node;

/**
 *
 * 
 */
@XmlType(namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
public class SecurityHeaderType {
    @XmlElement(namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
    public UsernameTokenType UsernameToken;
    static public UsernameTokenType parseUsernameToken(Object Security)
    {
        if (Security instanceof SecurityHeaderType)
            return ((SecurityHeaderType)Security).UsernameToken;
        UsernameTokenType result = null;
        try
        {
            Node SecurityN = (Node)Security;
            Node untN = null;
            for (int n = 0; n < SecurityN.getChildNodes().getLength(); n++)
            {
                Node nd = SecurityN.getChildNodes().item(n);                
                if (nd.getLocalName().equals("UsernameToken"))
                {
                    untN = nd;
                } 
            }
            if (untN != null)
            {
                result = new UsernameTokenType(); 
                for (int n = 0; n < untN.getChildNodes().getLength(); n++)
                {
                    Node nd = untN.getChildNodes().item(n);    
                    switch(nd.getLocalName())
                    {
                        case "Username":
                            result.username = nd.getTextContent();
                            break;
                        case "Password":
                            result.password = nd.getTextContent();
                            break;
                        case "Nonce":
                            result.nonce = nd.getTextContent();
                            break;
                        case "Created":
                            result.created = nd.getTextContent();
                            break;
                        default:
                            break;
                    }           
                }
            }
        }
        catch(Exception ex){}
        return result;
    }
}