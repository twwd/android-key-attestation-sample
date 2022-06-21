package de.twwd.keyattestationsample.crypto

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec

interface KeyManager {
    fun isKeyGenerated(): Boolean
    fun generateKey(challenge: ByteArray?): PublicKey
    fun deleteKey()

    fun loadKeyAttestationCertificateChain(): List<ByteArray>?

    /**
     * Checks if the device has a hardware trusted security module (TPM)
     */
    fun hasStrongbox(): Boolean
}

class KeyManagerFake(
    private val isKeyGenerated: Boolean = true,
    private val hasStrongbox: Boolean = true
) : KeyManager {
    override fun isKeyGenerated(): Boolean {
        return isKeyGenerated
    }

    override fun deleteKey() {}

    override fun generateKey(challenge: ByteArray?): PublicKey {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        val pair: KeyPair = keyGen.generateKeyPair()
        return pair.public
    }

    override fun loadKeyAttestationCertificateChain(): List<ByteArray> {
        return emptyList()
    }

    override fun hasStrongbox(): Boolean {
        return hasStrongbox
    }
}

class KeyManagerImpl(
    private val context: Context,
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
) : KeyManager {

    companion object {
        const val KEY_ALIAS = "de.twwd.keyattestationsample.key"
    }

    override fun isKeyGenerated(): Boolean {
        keyStore.apply {
            load(null)
            return containsAlias(KEY_ALIAS)
        }
    }

    override fun generateKey(challenge: ByteArray?): PublicKey {
        val keyPairGenerator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val parameterSpec =
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                // most Strongbox implementations only support a subset of digests, so we only declare what we really use
                // if we want to use stronger digests in the future, users will have to upgrade their keys
                .setDigests(KeyProperties.DIGEST_SHA256)
                // require the user to authenticate before using this key - this requires biometry
                .setUserAuthenticationRequired(true)


        challenge?.let {
            parameterSpec.setAttestationChallenge(it)
        }

        // Setting timeout to zero will prompt the user to authenticate every time the key is used
        // that's not a bad idea, but android only allows that when biometric authentication is
        // enabled.
        val timeout = 30
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            parameterSpec.setUserAuthenticationParameters(
                timeout,
                KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        } else {
            parameterSpec.setUserAuthenticationValidityDurationSeconds(timeout)
        }

        // store the key in the Trusted Platform Module if available
        @SuppressLint("NewApi")
        if (hasStrongbox()) {
            parameterSpec.setIsStrongBoxBacked(true)
        }

        keyPairGenerator.initialize(parameterSpec.build())
        return keyPairGenerator.generateKeyPair().public
    }

    override fun deleteKey() {
        keyStore.apply {
            load(null)
            if (containsAlias(KEY_ALIAS)) {
                deleteEntry(KEY_ALIAS)
            }
        }
    }

    override fun loadKeyAttestationCertificateChain(): List<ByteArray> {
        keyStore.apply {
            load(null)
            if (containsAlias(KEY_ALIAS)) {
                return getCertificateChain(KEY_ALIAS).map { it.encoded }
            }
        }
        throw RuntimeException("Certificate chain could not be loaded")
    }

    /**
     * Checks if the device has a hardware trusted security module (TPM)
     */
    override fun hasStrongbox(): Boolean {
        return context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }
}