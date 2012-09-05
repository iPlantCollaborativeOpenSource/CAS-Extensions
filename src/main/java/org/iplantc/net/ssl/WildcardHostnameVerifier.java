package org.iplantc.net.ssl;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import org.apache.commons.lang.StringUtils;

/**
 * A host name verifier that handles wildcard certificates.
 * 
 * @author Dennis Roberts
 */
public class WildcardHostnameVerifier implements HostnameVerifier {

    /**
     * The regular expression pattern used to extract the common name from the distinguished name in the certificate.
     */
    private static final Pattern CN_PATTERN = Pattern.compile("CN=([^,]+)");

    /**
     * Verifies a host name against the host name in an X.509 certificate.  If the host names match exactly then
     * the host name is accepted.  Otherwise, the host name associated with the certificate is checked for wildcard
     * characters (currently, only '*' is supported).  If the host name contains supported wildcard characters and
     * it matches the given host name then verification succeeds.
     * 
     * @param hostname the host name.
     * @param session the SSL session used on the connection to the host.
     * @return true if the host name is acceptable.
     */
    @Override
    public boolean verify(String hostname, SSLSession session) {
        try {
            X509Certificate peerCert = getPeerCert(session);
            String certHost = getCertHost(peerCert);
            validateHostName(hostname, certHost);
            return true;
        }
        catch (SSLPeerUnverifiedException e) {
            return false;
        }
    }

    /**
     * Obtains the peer certificate from the SSL session.
     * 
     * @param session the SSL session used on the connection to the remote host.
     * @return the X.509 certificate provided by the remote host.
     * @throws SSLPeerUnverifiedException if remote host's certificate is not an X.509 certificate.
     */
    private X509Certificate getPeerCert(SSLSession session) throws SSLPeerUnverifiedException {
        Certificate[] certs = session.getPeerCertificates();
        if (certs[0] instanceof X509Certificate) {
            return (X509Certificate) certs[0];
        }
        else {
            throw new SSLPeerUnverifiedException("peer certificate is not an X.509 certificate");
        }
    }

    /**
     * Obtains host name from an X.509 certificate.
     * 
     * @param cert the certificate to obtain the host name from.
     * @return the host name.
     * @throws SSLPeerUnverifiedException if the host name can't be determined.
     */
    private String getCertHost(X509Certificate cert) throws SSLPeerUnverifiedException {
        String dn = cert.getSubjectX500Principal().getName();
        String cn = null;
        if (dn != null) {
            Matcher matcher = CN_PATTERN.matcher(dn);
            if (matcher.find()) {
                cn = matcher.group(1);
            }
        }
        if (cn == null) {
            throw new SSLPeerUnverifiedException("peer certificate does not contain a common name");
        }
        return cn;
    }

    /**
     * Determines if the certificate host name matches the name of the host that we connected to.  This is true if
     * the host names are identical or the certificate host name contains a wildcard and the rest of the host name
     * pattern matches.
     * 
     * @param hostname the name of the host that we connected to.
     * @param certHost the name of the host provided in the certificate.
     * @throws SSLPeerUnverifiedException if the host names do not match.
     */
    private void validateHostName(String hostname, String certHost) throws SSLPeerUnverifiedException {
        if (StringUtils.equals(hostname, certHost)) {
            return;
        }
        else if (certHost.contains("*") && hostNameToRegex(certHost).matcher(hostname).matches()) {
            return;
        }
        throw new SSLPeerUnverifiedException("provided host name does not match host name in certificate");
    }

    /**
     * Converts a host name containing a wildcard character to a regular expression.
     * 
     * @param hostname the host name to convert.
     * @return the regular expression pattern.
     */
    private Pattern hostNameToRegex(String hostname) {
        StringBuilder builder = new StringBuilder();
        String[] components = hostname.split("\\*", -1);
        builder.append("\\Q").append(components[0]).append("\\E");
        for (int i = 1; i < components.length; i++) {
            builder.append("[^.]*").append("\\Q").append(components[i]).append("\\E");
        }
        return Pattern.compile(builder.toString());
    }
}
