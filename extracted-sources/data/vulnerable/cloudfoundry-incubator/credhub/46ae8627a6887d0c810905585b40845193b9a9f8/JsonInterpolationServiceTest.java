package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.helper.JsonTestHelper.deserialize;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class JsonInterpolationServiceTest {

  private JsonInterpolationService subject;
  private Map<String, Object> response;
  private List<EventAuditRecordParameters> eventAuditRecordParameters;
  private CredentialDataService credentialDataService;

  @Before
  public void beforeEach() {
    credentialDataService = mock(CredentialDataService.class);

    subject = new JsonInterpolationService(credentialDataService);
    eventAuditRecordParameters = new ArrayList<>();
  }

  @Test
  public void interpolateCredHubReferences_replacesTheCredHubRefWithSomethingElse() throws Exception {
    setupValidRequest();

    final ArrayList firstService = (ArrayList) response.get("pp-config-server");
    final ArrayList secondService = (ArrayList) response.get("pp-something-else");

    Map<String, Object> firstCredentialsBlock = (Map<String, Object>) ((Map<String, Object>) firstService.get(0)).get("credentials");
    Map<String, Object> secondCredentialsBlock = (Map<String, Object>) ((Map<String, Object>) firstService.get(1)).get("credentials");

    Map<String, Object> secondServiceCredentials = (Map<String, Object>) ((Map<String, Object>) secondService.get(0)).get("credentials");


    assertThat(firstCredentialsBlock.get("credhub-ref"), nullValue());
    assertThat(firstCredentialsBlock.size(), equalTo(1));
    assertThat(firstCredentialsBlock.get("secret1"), equalTo("secret1-value"));

    assertThat(secondCredentialsBlock.get("credhub-ref"), nullValue());
    assertThat(secondCredentialsBlock.size(), equalTo(1));
    assertThat(secondCredentialsBlock.get("secret2"), equalTo("secret2-value"));

    assertThat(secondServiceCredentials.get("credhub-ref"), nullValue());
    assertThat(secondServiceCredentials.size(), equalTo(2));
    assertThat(secondServiceCredentials.get("secret3-1"), equalTo("secret3-1-value"));
    assertThat(secondServiceCredentials.get("secret3-2"), equalTo("secret3-2-value"));
  }

  @Test
  public void interpolateCredHubReferences_updatesTheEventAuditRecordParameters() throws Exception {
    setupValidRequest();

    assertThat(eventAuditRecordParameters, hasSize(3));
    assertThat(eventAuditRecordParameters, containsInAnyOrder(
        samePropertyValuesAs(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred1")),
        samePropertyValuesAs(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred2")),
        samePropertyValuesAs(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/cred3"))));
  }

  @Test
  public void interpolateCredHubReferences_whenAReferencedCredentialIsNotJsonType_itThrowsAnException() throws Exception {
      String inputJson = "{"
          + "  \"pp-config-server\": ["
          + "    {"
          + "      \"credentials\": {"
          + "        \"credhub-ref\": \"((/password_cred))\""
          + "      },"
          + "      \"label\": \"pp-config-server\""
          + "    }"
          + "  ]"
          + "}";

      PasswordCredential passwordCredential = mock(PasswordCredential.class);
      when(passwordCredential.getName()).thenReturn("/password_cred");

      doReturn(
          passwordCredential
      ).when(credentialDataService).findMostRecent("/password_cred");

      try {
        subject.interpolateCredHubReferences(deserialize(inputJson, Map.class),
            eventAuditRecordParameters);
      } catch (ParameterizedValidationException exception) {
        assertThat(exception.getMessage(), equalTo("error.interpolation.invalid_type"));
        assertThat(eventAuditRecordParameters, hasSize(1));
        assertThat(eventAuditRecordParameters, contains(
            samePropertyValuesAs(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/password_cred"))
        ));
      }
  }

  @Test
  public void interpolateCredHubReferences_whenAReferencedCredentialDoesNotExist_itThrowsAnException() {
    String inputJsonString = "{"
        + "  \"pp-config-server\": ["
        + "    {"
        + "      \"credentials\": {"
        + "        \"credhub-ref\": \"((/missing_cred))\""
        + "      },"
        + "      \"label\": \"pp-config-server\""
        + "    }"
        + "  ]"
        + "}";
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);

    doReturn(
        null
    ).when(credentialDataService).findMostRecent("/missing_cred");

    try {
      subject.interpolateCredHubReferences(inputJson, eventAuditRecordParameters);
    } catch (ParameterizedValidationException exception) {
      assertThat(exception.getMessage(), equalTo("error.credential.invalid_access"));

      assertThat(eventAuditRecordParameters, hasSize(1));
      assertThat(eventAuditRecordParameters, contains(
          samePropertyValuesAs(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/missing_cred"))
      ));
    }
  }

  @Test
  public void interpolateCredHubReferences_whenTheServicePropertiesLackCredentials_doesNotInterpolateIt() {
    Map<String, Object> inputJson = deserialize("{"
        + "  \"pp-config-server\": [{"
        + "    \"blah\": {"
        + "      \"credhub-ref\": \"((/cred1))\""
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }]"
        + "}", Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson, eventAuditRecordParameters);

    assertThat(response, equalTo(inputJson));
    assertThat(eventAuditRecordParameters, hasSize(0));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsPropertyHasNoRefs_doesNotInterpolateIt() {
    Map<String, Object> inputJson = deserialize("{"
        + "  \"pp-config-server\": [{"
        + "    \"credentials\": {"
        + "      \"key\": \"((value))\""
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }]"
        + "}", Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson, eventAuditRecordParameters);

    assertThat(response, equalTo(inputJson));
    assertThat(eventAuditRecordParameters, hasSize(0));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsPropertyIsFormattedUnexpectedly_doesNotInterpolateIt() {
    String inputJsonString = "{"
            + "  \"pp-config-server\": [{"
            + "    \"foo\": {"
            + "      \"credentials\": {"
            + "        \"credhub-ref\": \"((/cred1))\""
            + "       }"
            + "     },"
            + "    \"label\": \"pp-config-server\""
            + "  }]"
            + "}";
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson, eventAuditRecordParameters);

    assertThat(response, equalTo(inputJson));
    assertThat(eventAuditRecordParameters, hasSize(0));
  }

  @Test
  public void interpolateCredHubReferences_whenThePropertiesAreNotAHash_doesNotInterpolateIt() {
    String inputJsonString = "{"
        + "  \"pp-config-server\": [\"what is this?\"]"
        + "}";
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson, eventAuditRecordParameters);

    assertThat(response, equalTo(inputJson));
    assertThat(eventAuditRecordParameters, hasSize(0));
  }

  @Test
  public void interpolateCredHubReferences_whenTheCredentialsAreNotAHashInAnArray_doesNotInterpolateIt() {
    String inputJsonString = "{"
        + "  \"pp-config-server\": [{"
        + "    \"credentials\": \"moose\","
        + "    \"label\": \"squirrel\""
        + "  }]"
        + "}";
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson, eventAuditRecordParameters);

    assertThat(response, equalTo(inputJson));
    assertThat(eventAuditRecordParameters, hasSize(0));
  }

  @Test
  public void interpolateCredHubReferences_whenPropertiesAreEmpty_doesNotInterpolateIt() {
    Map<String, Object> inputJson = deserialize("{}", Map.class);
    Map<String, Object> response = subject
        .interpolateCredHubReferences(inputJson, eventAuditRecordParameters);

    assertThat(response, equalTo(inputJson));
    assertThat(eventAuditRecordParameters, hasSize(0));
  }

  @Test
  public void interpolateCredHubReferences_whenServicePropertiesAreNotArrays_doesNotInterpolateIt() {
    String inputJsonString = "{"
        + "  \"pp-config-server\": {"
        + "    \"credentials\": {"
        + "      \"credhub-ref\": \"((/cred1))\""
        + "     },"
        + "    \"label\": \"pp-config-server\""
        + "  }"
        + "}";
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);
    Map response = subject.interpolateCredHubReferences(inputJson, eventAuditRecordParameters);

    assertThat(response, equalTo(inputJson));
    assertThat(eventAuditRecordParameters, hasSize(0));
  }

  private void setupValidRequest() {
    String inputJsonString = "{"
        + "  \"pp-config-server\": ["
        + "    {"
        + "      \"credentials\": {"
        + "        \"credhub-ref\": \"((/cred1))\""
        + "      },"
        + "      \"label\": \"pp-config-server\""
        + "    },"
        + "    {"
        + "      \"credentials\": {"
        + "        \"credhub-ref\": \"((/cred2))\""
        + "      }"
        + "    }"
        + "  ],"
        + "  \"pp-something-else\": ["
        + "    {"
        + "      \"credentials\": {"
        + "        \"credhub-ref\": \"((/cred3))\""
        + "      },"
        + "      \"something\": [\"pp-config-server\"]"
        + "    }"
        + "  ]"
        + "}";
    Map<String, Object> inputJson = deserialize(inputJsonString, Map.class);

    JsonCredential jsonCredential = mock(JsonCredential.class);
    when(jsonCredential.getName()).thenReturn("/cred1");
    doReturn(Maps.newHashMap("secret1", "secret1-value")).when(jsonCredential).getValue();

    JsonCredential jsonCredential1 = mock(JsonCredential.class);
    when(jsonCredential1.getName()).thenReturn("/cred2");
    doReturn(Maps.newHashMap("secret2", "secret2-value")).when(jsonCredential1).getValue();

    JsonCredential jsonCredential2 = mock(JsonCredential.class);
    when(jsonCredential2.getName()).thenReturn("/cred3");
    Map<String, String> jsonCredetials = Maps.newHashMap("secret3-1", "secret3-1-value");
    jsonCredetials.put("secret3-2", "secret3-2-value");
    doReturn(jsonCredetials).when(jsonCredential2).getValue();

    doReturn(
        jsonCredential
    ).when(credentialDataService).findMostRecent("/cred1");

    doReturn(
        jsonCredential1
    ).when(credentialDataService).findMostRecent("/cred2");

    doReturn(
        jsonCredential2
    ).when(credentialDataService).findMostRecent("/cred3");

    response = subject.interpolateCredHubReferences(inputJson, eventAuditRecordParameters);
  }
}

