package ru.vershinin.utils;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("CIT_RESPONSE")
public class CitResponse {
    private SystemData SYSTEM;
    private ResponseData DATA;

    public SystemData getSYSTEM() {
        return SYSTEM;
    }

    public void setSYSTEM(SystemData SYSTEM) {
        this.SYSTEM = SYSTEM;
    }

    public ResponseData getDATA() {
        return DATA;
    }

    public void setDATA(ResponseData DATA) {
        this.DATA = DATA;
    }

    @XStreamAlias("SYSTEM")
    public static class SystemData {
        private Err ERR;

        public Err getERR() {
            return ERR;
        }

        public void setERR(Err ERR) {
            this.ERR = ERR;
        }
    }

    @XStreamAlias("ERR")
    public static class Err {
        @XStreamAlias("Value")
        private String value;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

    @XStreamAlias("DATA")
    public static class ResponseData {
        private Body BODY;

        public Body getBODY() {
            return BODY;
        }

        public void setBODY(Body BODY) {
            this.BODY = BODY;
        }
    }

    @XStreamAlias("BODY")
    public static class Body {
        private String messageId;

        public String getMessageId() {
            return messageId;
        }

        public void setMessageId(String messageId) {
            this.messageId = messageId;
        }
    }

}

