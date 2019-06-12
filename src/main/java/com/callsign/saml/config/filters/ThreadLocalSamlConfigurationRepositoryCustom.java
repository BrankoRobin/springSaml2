package com.callsign.saml.config.filters;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;

import java.time.Clock;

public class ThreadLocalSamlConfigurationRepositoryCustom implements SamlConfigurationRepository {
    private static InheritableThreadLocal<ThreadLocalSamlConfigurationRepositoryCustom.ExpiringEntry> threadLocal = new InheritableThreadLocal();
    private final SamlConfigurationRepository initialValueProvider;
    private final Clock clock;
    private long expirationMillis;

    public ThreadLocalSamlConfigurationRepositoryCustom(SamlConfigurationRepository initialValueProvider) {
        this(initialValueProvider, Clock.systemUTC());
    }

    public ThreadLocalSamlConfigurationRepositoryCustom(SamlConfigurationRepository initialValueProvider, Clock clock) {
        this.expirationMillis = 10000L;
        this.initialValueProvider = initialValueProvider;
        this.clock = clock;
    }

    public SamlServerConfiguration getServerConfiguration() {
        ThreadLocalSamlConfigurationRepositoryCustom.ExpiringEntry expiringEntry = (ThreadLocalSamlConfigurationRepositoryCustom.ExpiringEntry) threadLocal.get();
        SamlServerConfiguration result = null;
        if (expiringEntry != null) {
            result = expiringEntry.getConfiguration(this.getExpirationMillis());
            if (result == null) {
                this.reset();
            }
        }

        if (result == null) {
            try {
                result = this.initialValueProvider.getServerConfiguration().clone();
            } catch (CloneNotSupportedException var4) {
                throw new SamlException(var4);
            }
        }

        return result;
    }

    protected void setServerConfiguration(SamlServerConfiguration configuration) {
        if (configuration == null) {
            this.reset();
        } else {
            threadLocal.set(new ThreadLocalSamlConfigurationRepositoryCustom.ExpiringEntry(this.clock, configuration));
        }

    }

    public void reset() {
        threadLocal.remove();
    }

    public long getExpirationMillis() {
        return this.expirationMillis;
    }

    public ThreadLocalSamlConfigurationRepositoryCustom setExpirationMillis(long expirationMillis) {
        this.expirationMillis = expirationMillis;
        return this;
    }

    private static class ExpiringEntry {
        private Clock clock;
        private long created;
        private SamlServerConfiguration configuration;

        public ExpiringEntry(Clock clock, SamlServerConfiguration configuration) {
            this.clock = clock;
            this.setConfiguration(configuration);
        }

        public long getCreated() {
            return this.created;
        }

        public void setConfiguration(SamlServerConfiguration configuration) {
            this.configuration = configuration;
            this.created = configuration == null ? 0L : this.clock.millis();
        }

        public SamlServerConfiguration getConfiguration(long expiration) {
            return this.created + expiration > this.clock.millis() ? this.configuration : null;
        }
    }
}
