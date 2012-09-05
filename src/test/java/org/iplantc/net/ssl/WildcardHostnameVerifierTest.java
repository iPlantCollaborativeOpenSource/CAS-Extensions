package org.iplantc.net.ssl;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.auth.x500.X500Principal;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


/**
 * Unit tests for WildcardHostnameVerifier.
 * 
 * @author Dennis Roberts
 */
public class WildcardHostnameVerifierTest {
    
    /**
     * Verifies that validation passes when the host names are identical.
     */
    @Test
    public void identicalHostNamesShouldPass() {
        assertTrue(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("CN=foo.bar.org")));
    }

    /**
     * Verifies that validation fails when the host names are different.
     */
    @Test
    public void differentHostamesShouldFail() {
        assertFalse(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("CN=foo.bar.com")));
    }

    /**
     * Verifies that validation passes when the host name matches the wildcard pattern.
     */
    @Test
    public void wildcardNamesShouldPass() {
        assertTrue(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("CN=*.bar.org")));
    }

    /**
     * Verifies that validation fails when the wildcard would have to match a period to succeed.
     */
    @Test
    public void wildcardNamesShouldNotMatchPeriods() {
        assertFalse(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("CN=*.org")));
    }

    /**
     * Verifies that validation fails if there's a wildcard pattern that doesn't match.
     */
    @Test
    public void wildcardNamesThatDoNotMatchShouldFail() {
        assertFalse(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("CN=*.bar.com")));
    }

    /**
     * Verifies that validation passes if there's a wildcard in the middle.
     */
    @Test
    public void wildcardsInMiddleShouldPass() {
        assertTrue(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("CN=foo.*.org")));
    }

    /**
     * Verifies that validation fails if there's a wildcard in the middle of a non-matching pattern.
     */
    @Test
    public void wildcardsInMiddleWithNonMatchingPatternShouldFail() {
        assertFalse(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("CN=bar.*.org")));
    }

    /**
     * Verifies that validation passes if there's a wildcard at the end of a matching pattern.
     */
    @Test
    public void wildcardsAtEndShouldPass() {
        assertTrue(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("CN=foo.bar.*")));
    }

    /**
     * Verifies that validation fails if there's a wildcard at the end of a non-matching pattern.
     */
    @Test
    public void wildcardsAtEndOfNonMatchingPatternShouldFail() {
        assertFalse(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("CN=foo.baz.*")));
    }

    /**
     * Verifies that validation fails if the certificate has no common name.
     */
    @Test
    public void distinguishedNameWithoutCommonNameShouldFail() {
        assertFalse(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession("L=Nowhere")));
    }

    /**
     * Verifies that validation fails if the peer certificate is not an X.509 certificate.
     */
    @Test
    public void validationShouldFailIfCertIsNotX509() {
        assertFalse(new WildcardHostnameVerifier().verify("foo.bar.org", new MockSslSession(new GenericMockCert())));
    }

    /**
     * A mock SSL session for testing.
     */
    private class MockSslSession implements SSLSession {

        private Certificate[] certs;

        public MockSslSession(Certificate cert) {
            certs = new Certificate[1];
            certs[0] = cert;
        }

        public MockSslSession(String principalName) {
            this(new MockCert(principalName));
        }

        public MockSslSession() {
            this(new MockCert());
        }

        @Override
        public byte[] getId() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public SSLSessionContext getSessionContext() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public long getCreationTime() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public long getLastAccessedTime() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void invalidate() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean isValid() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void putValue(String string, Object o) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Object getValue(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void removeValue(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String[] getValueNames() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
            return certs;
        }

        @Override
        public Certificate[] getLocalCertificates() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Principal getLocalPrincipal() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getCipherSuite() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getProtocol() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getPeerHost() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getPeerPort() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getPacketBufferSize() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getApplicationBufferSize() {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        
    }

    /**
     * A mock certificate to use for testing.
     */
    private class MockCert extends X509Certificate {

        private X500Principal principal;

        public MockCert(String principalName) {
            principal = new X500Principal(principalName);
        }

        public MockCert() {
            principal = new X500Principal((String) null);
        }

        @Override
        public X500Principal getSubjectX500Principal() {
            return principal;
        }

        @Override
        public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getVersion() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public BigInteger getSerialNumber() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Principal getIssuerDN() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Principal getSubjectDN() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Date getNotBefore() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Date getNotAfter() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] getTBSCertificate() throws CertificateEncodingException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] getSignature() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getSigAlgName() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getSigAlgOID() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] getSigAlgParams() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean[] getIssuerUniqueID() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean[] getSubjectUniqueID() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean[] getKeyUsage() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public int getBasicConstraints() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] getEncoded() throws CertificateEncodingException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void verify(PublicKey pk) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
                NoSuchProviderException, SignatureException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void verify(PublicKey pk, String string) throws CertificateException, NoSuchAlgorithmException,
                InvalidKeyException, NoSuchProviderException, SignatureException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String toString() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public PublicKey getPublicKey() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public boolean hasUnsupportedCriticalExtension() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Set<String> getCriticalExtensionOIDs() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Set<String> getNonCriticalExtensionOIDs() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] getExtensionValue(String string) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }

    private class GenericMockCert extends Certificate {

        public GenericMockCert() {
            super(null);
        }

        @Override
        public byte[] getEncoded() throws CertificateEncodingException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void verify(PublicKey pk) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
                NoSuchProviderException, SignatureException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void verify(PublicKey pk, String string) throws CertificateException, NoSuchAlgorithmException,
                InvalidKeyException, NoSuchProviderException, SignatureException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String toString() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public PublicKey getPublicKey() {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        
    }
}
