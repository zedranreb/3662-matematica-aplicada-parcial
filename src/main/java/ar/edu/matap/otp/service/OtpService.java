package ar.edu.matap.otp.service;

import ar.edu.matap.otp.crypto.Base32;
import ar.edu.matap.otp.crypto.Hotp;
import ar.edu.matap.otp.crypto.Totp;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HashMap;

/**
 * Estado de la simulación (en memoria): un secreto compartido K entre el token y el servidor,
 * y los contadores HOTP de cada lado, que pueden desincronizarse.
 */
@Service
public class OtpService {
    public static final int DIGITS = 6;
    public static final int PERIOD = 30;
    /** Ventana de resincronización HOTP (parámetro "s" del RFC 4226). */
    public static final int LOOK_AHEAD = 5;
    /** Secreto de los vectores de prueba de los RFC: ASCII "12345678901234567890". */
    public static final String RFC_SECRET = Base32.encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

    private final SecureRandom random = new SecureRandom();
    private byte[] key;
    private long tokenCounter;
    private long serverCounter;
    private final Map<String, Long> lastAcceptedTotpCounterBySecret =
            new HashMap<>();

    public OtpService() {
        newRandomSecret();
    }

    public synchronized Map<String, Object> state() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("secret", Base32.encode(key));
        m.put("secretBytes", key.length);
        m.put("digits", DIGITS);
        m.put("period", PERIOD);
        m.put("lookAhead", LOOK_AHEAD);
        m.put("tokenCounter", tokenCounter);
        m.put("serverCounter", serverCounter);
        return m;
    }

    public synchronized void newRandomSecret() {
        byte[] k = new byte[20]; // 160 bits, el largo recomendado para HMAC-SHA1
        random.nextBytes(k);
        setKey(k);
    }

    public synchronized void setSecret(String base32) {
        if (base32 == null || base32.isBlank()) {
            throw new IllegalArgumentException("Ingresá un secreto en Base32.");
        }
        byte[] k = Base32.decode(base32);
        if (k.length < 16) {
            throw new IllegalArgumentException(
                    "El secreto es demasiado corto: se requieren al menos 128 bits (16 bytes).");
        }
        setKey(k);
    }


    private void setKey(byte[] k) {
        this.key = k;
        this.tokenCounter = 0;
        this.serverCounter = 0;
    }


    public synchronized void resetCounters() {
        tokenCounter = 0;
        serverCounter = 0;
    }

    /** Código TOTP vigente, visto desde el token. */
    public synchronized Map<String, Object> currentTotp() {
        long nowMs = System.currentTimeMillis();
        Hotp.Trace trace = Totp.trace(key, nowMs / 1000, PERIOD, DIGITS);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("code", trace.code());
        m.put("epochSeconds", nowMs / 1000);
        m.put("remainingMs", PERIOD * 1000L - (nowMs % (PERIOD * 1000L)));
        m.put("trace", trace);
        return m;
    }

    /** El usuario "presiona el botón" del token HOTP: genera un código y avanza su contador. */
    public synchronized Map<String, Object> nextHotp() {
        Hotp.Trace trace = Hotp.trace(key, tokenCounter, DIGITS);
        tokenCounter++;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("code", trace.code());
        m.put("trace", trace);
        m.put("tokenCounter", tokenCounter);
        m.put("serverCounter", serverCounter);
        return m;
    }

    /** Validación en el rol de servidor. */
    public synchronized Map<String, Object> verify(String mode, String code) {
        if (code == null || !code.matches("\\d{" + DIGITS + "}")) {
            throw new IllegalArgumentException("El código debe tener exactamente " + DIGITS + " dígitos numéricos.");
        }
        Map<String, Object> m = new LinkedHashMap<>();


        if ("TOTP".equalsIgnoreCase(mode)) {
            long now = System.currentTimeMillis() / 1000;
            Hotp.Trace expected = Totp.trace(key, now, PERIOD, DIGITS);

            // Identificamos el secreto utilizado.
            String secretId = Base32.encode(key);

            // Recuperamos el último intervalo aceptado para ese secreto.
            long lastAccepted = lastAcceptedTotpCounterBySecret
                    .getOrDefault(secretId, -1L);

            boolean matches = constantTimeEquals(expected.code(), code);
            boolean alreadyUsed = expected.counter() <= lastAccepted;
            boolean ok = matches && !alreadyUsed;

            if (ok) {
                lastAcceptedTotpCounterBySecret.put(
                        secretId, expected.counter());
            }

            m.put("valid", ok);
            m.put("message", ok
                    ? "Código válido para el intervalo T = "
                    + expected.counter() + "."
                    : matches && alreadyUsed
                    ? "Código rechazado: este intervalo TOTP ya fue "
                    + "utilizado o es anterior a uno aceptado."
                    : "Código inválido o vencido: no coincide con "
                    + "el del intervalo T = "
                    + expected.counter() + ".");
            m.put("trace", expected);
        } else if ("HOTP".equalsIgnoreCase(mode)) {
            boolean ok = false;
            for (int i = 0; i <= LOOK_AHEAD && !ok; i++) {
                Hotp.Trace t = Hotp.trace(key, serverCounter + i, DIGITS);
                if (constantTimeEquals(t.code(), code)) {
                    ok = true;
                    m.put("message", i == 0
                            ? "Código válido para el contador C = " + t.counter() + "."
                            : "Código válido. El token estaba " + i + " paso(s) adelantado: el servidor se resincronizó a C = "
                              + (t.counter() + 1) + ".");
                    m.put("trace", t);
                    serverCounter = t.counter() + 1;
                }
            }
            if (!ok) {
                m.put("message", "Código inválido: no coincide con ningún contador entre C = " + serverCounter
                        + " y C = " + (serverCounter + LOOK_AHEAD) + " (ya fue usado o el token está fuera de la ventana).");
                m.put("trace", Hotp.trace(key, serverCounter, DIGITS));
            }
            m.put("valid", ok);
        } else {
            throw new IllegalArgumentException("Modo desconocido: usá TOTP o HOTP.");
        }
        m.put("tokenCounter", tokenCounter);
        m.put("serverCounter", serverCounter);
        return m;
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.US_ASCII), b.getBytes(StandardCharsets.US_ASCII));
    }
}
