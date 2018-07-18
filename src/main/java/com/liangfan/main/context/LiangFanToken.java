package com.liangfan.main.context;

import com.liangfan.main.util.OAuthToken;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.IOException;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LiangFanToken {
    private static final long serialVersionUID = 3891133932519746686L;

    public static LiangFanToken from(final String response) throws IOException {
        return LiangFanToken.parse(response);
    }

    private static LiangFanToken parse(final String response) {
        LiangFanToken token = null;
        try {
            final String[] strs = response.split("&");
            token = new LiangFanToken();
            for (final String str : strs) {
                if (str.startsWith("oauth_token=")) {
                    token.setToken(str.split("=")[1].trim());
                } else if (str.startsWith("oauth_token_secret=")) {
                    token.setTokenSecret(str.split("=")[1].trim());
                }
            }
        } catch (final Exception ignored) {
        }
        return token;
    }

    private String token;

    private String tokenSecret;


    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OAuthToken)) {
            return false;
        }

        final LiangFanToken that = (LiangFanToken) o;

        if (!this.token.equals(that.token)) {
            return false;
        }
        return this.tokenSecret.equals(that.tokenSecret);
    }

    public String getToken() {
        return this.token;
    }

    public String getTokenSecret() {
        return this.tokenSecret;
    }

    @Override
    public int hashCode() {
        int result = this.token.hashCode();
        result = (31 * result) + this.tokenSecret.hashCode();
        return result;
    }

    public boolean isNull() {
        return (this.token == null) || (this.tokenSecret == null);
    }

    private void setToken(final String token) {
        this.token = token;
    }

    private void setTokenSecret(final String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    @Override
    public String toString() {
        return "OAuthToken{" + "token='" + this.token + '\''
                + ", tokenSecret='" + this.tokenSecret + '}';
    }
}
