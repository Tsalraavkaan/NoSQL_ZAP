package org.zaproxy.zap.extension.ascanrules;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class MongoDbScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.mongodb.";
    /* Constants */
    private static final String ALL_DATA_ATTACK = "alldata";
    private static final String JSON_ATTACK = "json";
    private static final String AUTH_BYPASS_ATTACK = "authbypass";

    private static final String JSON_TOKEN = "$ZAP";
    /* Data for attack rules */
    private static final String[] ALL_DATA_PARAM_INJECTION =
            new String[] {"[$ne]", "[$regex]", "[$gt]", "[$eq]"};
    private static final String[] ALL_DATA_VALUE_INJECTION = new String[] {"", ".*", "0", ""};
    private static final String[][] JSON_INJECTION = {{"$ne", "0"}, {"$gt", ""}, {"$regex", ".*"}};
    /* Logger prints */
    private static final String JSON_EX_LOG = "trying to convert the payload in json format";
    private static final String IO_EX_LOG = "trying to send an http message";
    private static final String URI_EX_LOG = "trying to get the message's Uri";
    private static final String STOP_LOG = "Stopping the scan due to a user request";
    private static final Logger LOG = LogManager.getLogger(MongoDbScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION
                    CommonAlertTag.WSTG_V42_INPV_05_SQLI);

    @Override
    public int getId() {
        return 40123;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.MongoDB);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    public String getExtraInfo(String attack) {
        return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo." + attack);
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 1000;
    }

    @Override
    public int getWascId() {
        return 25;
    }

    // Init Variables
    private boolean isJsonPayload;
    private boolean doAllDataScan;
    private boolean doJsonScan;
    private boolean getMoreConfidence;
    private boolean doAuthBypass;

    @Override
    public void init() {
        LOG.debug("Initialising MongoDB penertration tests");
        switch (this.getAttackStrength()) {
            case LOW:
                doAllDataScan = true;
                doJsonScan = true;
                getMoreConfidence = false;
                doAuthBypass = true;
                break;
            default:
                doAllDataScan = true;
                doJsonScan = true;
                getMoreConfidence = true;
                doAuthBypass = true;
                break;
        }
    }

    /*
     * This method is called by the active scanner for each GET and POST parameter for every page
     * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
     */

    @Override
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        isJsonPayload = originalParam.getType() == NameValuePair.TYPE_JSON;
        super.scan(msg, originalParam);
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        boolean isFound = false;
        HttpMessage msgInjection;
        HttpMessage msgCounterProof;
        String bodyBase = getBaseMsg().getResponseBody().toString();

        LOG.debug("Scanning URL [{}] [{}] on param: [{}] with value: [{}] for MongoDB Injection",
                  msg.getRequestHeader().getMethod(),
                  msg.getRequestHeader().getURI(),
                  param,
                  value);
        // injection attack to url-encoded query parameters
        if (doAllDataScan && !isJsonPayload) {
            LOG.debug("Starting with boolean based attack payloads:");
            int index = 0;
            for (String valueInj : ALL_DATA_VALUE_INJECTION) {
                String paramInj = param + ALL_DATA_PARAM_INJECTION[index++];
                if (isStop()) {
                    LOG.debug(STOP_LOG);
                    return;
                }

                LOG.debug("Trying with the value: {} {}", paramInj, valueInj);
                try {
                    msgInjection = getNewMsg();
                    setParameter(msgInjection, paramInj, valueInj);
                    sendAndReceive(msgInjection, false);
                    String bodyInjAttack = msgInjection.getResponseBody().toString();
                    if (msgInjection.getResponseHeader().getStatusCode()
                            != getBaseMsg().getResponseHeader().getStatusCode()) {
                        continue;
                    }
                    if (!bodyBase.equals(bodyInjAttack)) {
                        msgCounterProof = getNewMsg();
                        setParameter(msgCounterProof, param + "[$eq]", value);
                        sendAndReceive(msgCounterProof, false);
                        String bodyCounterProof = msgCounterProof.getResponseBody().toString();
                        if (bodyBase.equals(bodyCounterProof)) {
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_HIGH)
                                    .setParam(param)
                                    .setAttack(paramInj + valueInj)
                                    .setOtherInfo(getExtraInfo(ALL_DATA_ATTACK))
                                    .setMessage(msgInjection)
                                    .raise();
                            isFound = true;
                            break;
                        }
                    }
                } catch (IOException ex) {
                    LOG.debug("Caught {} {} when {}",
                              ex.getClass().getName(),
                              ex.getMessage(),
                              URI_EX_LOG);
                    return;
                }
            }
        }
        // json query injection
        if (!isFound && doJsonScan && isJsonPayload) {
            LOG.debug("Starting with the json injection payloads:");
            for (String[] jpv : JSON_INJECTION) {
                try {
                    if (isStop()) {
                        LOG.debug(STOP_LOG);
                        return;
                    }
                    LOG.debug("Trying with the value: {}", jpv[0]);
                    String valueInj = getParamJsonString(param, jpv);
                    msgInjection = getNewMsg();
                    setParameter(msgInjection, param, valueInj);
                    sendAndReceive(msgInjection);
                    String bodyInjAttack = msgInjection.getResponseBody().toString();
                    if (msgInjection.getResponseHeader().getStatusCode()
                            != getBaseMsg().getResponseHeader().getStatusCode()) {
                        continue;
                    }
                    if (!bodyBase.equals(bodyInjAttack)) {
                        // Get more confidence
                        if (getMoreConfidence) {
                            String secondVal =
                                    getParamJsonString(param, new String[] {JSON_TOKEN, jpv[1]});
                            msgCounterProof = getNewMsg();
                            setParameter(msgCounterProof, param, secondVal);
                            sendAndReceive(msgCounterProof, false);
                            String bodyCounterProof = msgCounterProof.getResponseBody().toString();
                            if (bodyBase.equals(bodyCounterProof)) {
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_HIGH)
                                        .setParam(param)
                                        .setAttack(jpv[0] + jpv[1])
                                        .setOtherInfo(getExtraInfo(JSON_ATTACK))
                                        .setMessage(msgInjection)
                                        .raise();
                                isFound = true;
                                break;
                            }
                        } else {
                            newAlert()
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setParam(param)
                                    .setAttack(jpv[0] + jpv[1])
                                    .setOtherInfo(getExtraInfo(JSON_ATTACK))
                                    .setMessage(msgInjection)
                                    .raise();
                            isFound = true;
                            break;
                        }
                    }
                } catch (JSONException ex) {
                    LOG.debug("Caught {} {} when {}",
                              ex.getClass().getName(),
                              ex.getMessage(),
                              JSON_EX_LOG);
                    return;
                } catch (IOException ex) {
                    LOG.debug("Caught {} {} when {}",
                              ex.getClass().getName(),
                              ex.getMessage(),
                              URI_EX_LOG);
                    return;
                }
            }
        }
        // if a nosql injection was found, we should check if the page is flagged as a login page
        if (doAuthBypass && isFound) {
            if (isStop()) {
                LOG.debug(STOP_LOG);
                return;
            }
            LOG.debug("A vulnerability has been reported, check if it concerns an authentication page");
            ExtensionAuthentication extAuth =
                    (ExtensionAuthentication)
                            Control.getSingleton()
                                   .getExtensionLoader()
                                   .getExtension(ExtensionAuthentication.NAME);
            if (extAuth != null) {
                URI requestUri = getBaseMsg().getRequestHeader().getURI();
                try {
                    List<Context> contextList =
                            extAuth.getModel()
                                   .getSession()
                                   .getContextsForUrl(requestUri.toString());
                    for (Context context : contextList) {
                        URI loginUri = extAuth.getLoginRequestURIForContext(context);
                        if (loginUri != null) {
                            if (requestUri.getScheme().equals(loginUri.getScheme())
                                    && requestUri.getHost().equals(loginUri.getHost())
                                    && requestUri.getPort() == loginUri.getPort()
                                    && requestUri.getPath().equals(loginUri.getPath())) {
                                newAlert()
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setParam(param)
                                        .setOtherInfo(getExtraInfo(AUTH_BYPASS_ATTACK))
                                        .setMessage(getBaseMsg())
                                        .raise();
                                break;
                            }
                        }
                    }
                } catch (URIException ex) {
                    LOG.debug("Caught {} {} when {}",
                              ex.getClass().getName(),
                              ex.getMessage(),
                              URI_EX_LOG);
                }
            }
        }
    }

    private static String getParamJsonString(String param, String[] params) throws JSONException {
        JSONObject internal = new JSONObject(), external = new JSONObject();
        internal.put(params[0], params[1]);
        external.put(param, internal);
        return external.toString();
    }
}