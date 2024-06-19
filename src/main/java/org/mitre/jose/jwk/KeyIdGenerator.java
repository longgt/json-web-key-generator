package org.mitre.jose.jwk;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import com.github.f4b6a3.uuid.UuidCreator;
import com.google.common.hash.Hashing;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.StandardCharset;

/**
 * @author jricher
 *
 */
// KeyID generator functions
public class KeyIdGenerator {

    public static KeyIdGenerator TIMESTAMP = new KeyIdGenerator("timestamp", (params) -> {
        KeyUse use = (KeyUse) params.get(JWKParameterNames.PUBLIC_KEY_USE);
		return Optional.ofNullable(use).map(KeyUse::getValue).map(s -> s + "-").orElse("")
			+ Instant.now().getEpochSecond();
	});

    public static KeyIdGenerator DATE = new KeyIdGenerator("date", (params) -> {
        KeyUse use = (KeyUse) params.get(JWKParameterNames.PUBLIC_KEY_USE);
		return Optional.ofNullable(use).map(KeyUse::getValue).map(s -> s + "-").orElse("")
			+ Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
	});

    public static KeyIdGenerator SHA256 = new KeyIdGenerator("sha256", (params) -> {
        final String json = JSONObjectUtils.toJSONString(normalizeParams(params));
        byte[] bytes = Hashing.sha256().hashBytes(json.getBytes(StandardCharset.UTF_8)).asBytes();
		return Base64URL.encode(bytes).toString();
	});

    public static KeyIdGenerator SHA384 = new KeyIdGenerator("sha384", (params) -> {
        final String json = JSONObjectUtils.toJSONString(normalizeParams(params));
        byte[] bytes = Hashing.sha384().hashBytes(json.getBytes(StandardCharset.UTF_8)).asBytes();
        return Base64URL.encode(bytes).toString();
    });

    public static KeyIdGenerator SHA512 = new KeyIdGenerator("sha512", (params) -> {
        final String json = JSONObjectUtils.toJSONString(normalizeParams(params));
        byte[] bytes = Hashing.sha512().hashBytes(json.getBytes(StandardCharset.UTF_8)).asBytes();
        return Base64URL.encode(bytes).toString();
    });

    public static KeyIdGenerator UUIDv1 = new KeyIdGenerator("uuidv1", (params) -> {
        return UuidCreator.getTimeBasedWithRandom().toString();
    });

    public static KeyIdGenerator UUIDv4 = new KeyIdGenerator("uuidv4", (params) -> {
        return UuidCreator.getRandomBased().toString();
    });

    public static KeyIdGenerator UUIDv6 = new KeyIdGenerator("uuidv6", (params) -> {
        return UuidCreator.getTimeOrderedWithRandom().toString();
    });

    public static KeyIdGenerator UUIDv7 = new KeyIdGenerator("uuidv7", (params) -> {
        return UuidCreator.getTimeOrderedEpoch().toString();
    });

    public static KeyIdGenerator NONE = new KeyIdGenerator("none", (params) -> {
		return null;
	});

	private final String name;
    private final String alias;
    private final Function<Map<String, Object>, String> fn;

    public KeyIdGenerator(String name, Function<Map<String, Object>, String> fn) {
        this(name, name, fn);
	}

    public KeyIdGenerator(String name, String alias, Function<Map<String, Object>, String> fn) {
        this.name = name;
        this.alias = alias;
        this.fn = fn;
    }

    public String generate(final Map<String, Object> params) {
        return this.fn.apply(params);
	}

	public String getName() {
		return this.name;
	}

    public String getAlias() {
        return this.alias;
    }

    public boolean match(String name) {
        return this.name.equals(name) || this.alias.equals(name);
    }

	public static List<KeyIdGenerator> values() {
        return List.of(DATE, TIMESTAMP, SHA256, SHA384, SHA512, UUIDv1, UUIDv4, UUIDv6, UUIDv7, NONE);
	}

	public static KeyIdGenerator get(String name) {
		return values().stream()
                .filter(g -> g.match(name))
			.findFirst()
			.orElse(TIMESTAMP);
	}

	public static KeyIdGenerator specified(String kid) {
        return new KeyIdGenerator(null, (params) -> kid);
	}

    private static Map<String, Object> normalizeParams(final Map<String, Object> params) {
        Map<String, Object> requiredParams = new LinkedHashMap<>(params);
        requiredParams.remove(JWKParameterNames.PUBLIC_KEY_USE);

        return requiredParams;
    }
}

