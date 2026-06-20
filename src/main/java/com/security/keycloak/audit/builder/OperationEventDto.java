package com.security.keycloak.audit.builder;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OperationEventDto {

    @JsonProperty("enterprise_id")
    private String enterpriseId;

    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("user_name")
    private String userName;

    @JsonProperty("user_role")
    private List<String> userRole;

    @JsonProperty("operation_type")
    private String operationType;

    @JsonProperty("operation_at")
    private Instant operationAt;

    @JsonProperty("module_name")
    private String moduleName;

    @JsonProperty("affected_table")
    private String affectedTable;

    @JsonProperty("register_id")
    private String registerId;

    @JsonProperty("data_object")
    private Map<String, Object> dataObject;
}
