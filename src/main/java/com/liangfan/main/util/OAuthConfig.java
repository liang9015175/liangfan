/*******************************************************************************
 * Copyright 2011, 2012, 2013 fanfou.com, Xiaoke, Zhang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.liangfan.main.util;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * @author mcxiaoke
 * @version 1.1 2013.03.20
 */
@Data
public final class OAuthConfig {
    private String REQUEST_TOKEN_URL = "http://fanfou.com/oauth/request_token";
    private String AUTHORIZE_URL = "http://fanfou.com/oauth/authorize";
    private String ACCESS_TOKEN_URL = "http://fanfou.com/oauth/access_token";
    private String consumer_key = "112602aa9c7a3e967824a80aa04cb776";
    private String consumer_secret = "f3b32ae5cadac9a50da21f57df852f42";


}
