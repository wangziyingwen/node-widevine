import type { GenEnum, GenFile, GenMessage } from "@bufbuild/protobuf/codegenv1";
import type { Message } from "@bufbuild/protobuf";
export declare const file_license_protocol: GenFile;
export type LicenseIdentification = Message<"license_protocol.LicenseIdentification"> & {
    requestId: Uint8Array;
    sessionId: Uint8Array;
    purchaseId: Uint8Array;
    type: LicenseType;
    version: number;
    providerSessionToken: Uint8Array;
};
export declare const LicenseIdentificationSchema: GenMessage<LicenseIdentification>;
export type License = Message<"license_protocol.License"> & {
    id?: LicenseIdentification;
    policy?: License_Policy;
    key: License_KeyContainer[];
    licenseStartTime: bigint;
    remoteAttestationVerified: boolean;
    providerClientToken: Uint8Array;
    protectionScheme: number;
    srmRequirement: Uint8Array;
    srmUpdate: Uint8Array;
    platformVerificationStatus: PlatformVerificationStatus;
    groupIds: Uint8Array[];
};
export declare const LicenseSchema: GenMessage<License>;
export type License_Policy = Message<"license_protocol.License.Policy"> & {
    canPlay: boolean;
    canPersist: boolean;
    canRenew: boolean;
    rentalDurationSeconds: bigint;
    playbackDurationSeconds: bigint;
    licenseDurationSeconds: bigint;
    renewalRecoveryDurationSeconds: bigint;
    renewalServerUrl: string;
    renewalDelaySeconds: bigint;
    renewalRetryIntervalSeconds: bigint;
    renewWithUsage: boolean;
    alwaysIncludeClientId: boolean;
    playStartGracePeriodSeconds: bigint;
    softEnforcePlaybackDuration: boolean;
    softEnforceRentalDuration: boolean;
};
export declare const License_PolicySchema: GenMessage<License_Policy>;
export type License_KeyContainer = Message<"license_protocol.License.KeyContainer"> & {
    id: Uint8Array;
    iv: Uint8Array;
    key: Uint8Array;
    type: License_KeyContainer_KeyType;
    level: License_KeyContainer_SecurityLevel;
    requiredProtection?: License_KeyContainer_OutputProtection;
    requestedProtection?: License_KeyContainer_OutputProtection;
    keyControl?: License_KeyContainer_KeyControl;
    operatorSessionKeyPermissions?: License_KeyContainer_OperatorSessionKeyPermissions;
    videoResolutionConstraints: License_KeyContainer_VideoResolutionConstraint[];
    antiRollbackUsageTable: boolean;
    trackLabel: string;
};
export declare const License_KeyContainerSchema: GenMessage<License_KeyContainer>;
export type License_KeyContainer_KeyControl = Message<"license_protocol.License.KeyContainer.KeyControl"> & {
    keyControlBlock: Uint8Array;
    iv: Uint8Array;
};
export declare const License_KeyContainer_KeyControlSchema: GenMessage<License_KeyContainer_KeyControl>;
export type License_KeyContainer_OutputProtection = Message<"license_protocol.License.KeyContainer.OutputProtection"> & {
    hdcp: License_KeyContainer_OutputProtection_HDCP;
    cgmsFlags: License_KeyContainer_OutputProtection_CGMS;
    hdcpSrmRule: License_KeyContainer_OutputProtection_HdcpSrmRule;
    disableAnalogOutput: boolean;
    disableDigitalOutput: boolean;
};
export declare const License_KeyContainer_OutputProtectionSchema: GenMessage<License_KeyContainer_OutputProtection>;
export declare enum License_KeyContainer_OutputProtection_HDCP {
    HDCP_NONE = 0,
    HDCP_V1 = 1,
    HDCP_V2 = 2,
    HDCP_V2_1 = 3,
    HDCP_V2_2 = 4,
    HDCP_V2_3 = 5,
    HDCP_NO_DIGITAL_OUTPUT = 255
}
export declare const License_KeyContainer_OutputProtection_HDCPSchema: GenEnum<License_KeyContainer_OutputProtection_HDCP>;
export declare enum License_KeyContainer_OutputProtection_CGMS {
    CGMS_NONE = 42,
    COPY_FREE = 0,
    COPY_ONCE = 2,
    COPY_NEVER = 3
}
export declare const License_KeyContainer_OutputProtection_CGMSSchema: GenEnum<License_KeyContainer_OutputProtection_CGMS>;
export declare enum License_KeyContainer_OutputProtection_HdcpSrmRule {
    HDCP_SRM_RULE_NONE = 0,
    CURRENT_SRM = 1
}
export declare const License_KeyContainer_OutputProtection_HdcpSrmRuleSchema: GenEnum<License_KeyContainer_OutputProtection_HdcpSrmRule>;
export type License_KeyContainer_VideoResolutionConstraint = Message<"license_protocol.License.KeyContainer.VideoResolutionConstraint"> & {
    minResolutionPixels: number;
    maxResolutionPixels: number;
    requiredProtection?: License_KeyContainer_OutputProtection;
};
export declare const License_KeyContainer_VideoResolutionConstraintSchema: GenMessage<License_KeyContainer_VideoResolutionConstraint>;
export type License_KeyContainer_OperatorSessionKeyPermissions = Message<"license_protocol.License.KeyContainer.OperatorSessionKeyPermissions"> & {
    allowEncrypt: boolean;
    allowDecrypt: boolean;
    allowSign: boolean;
    allowSignatureVerify: boolean;
};
export declare const License_KeyContainer_OperatorSessionKeyPermissionsSchema: GenMessage<License_KeyContainer_OperatorSessionKeyPermissions>;
export declare enum License_KeyContainer_KeyType {
    SIGNING = 1,
    CONTENT = 2,
    KEY_CONTROL = 3,
    OPERATOR_SESSION = 4,
    ENTITLEMENT = 5,
    OEM_CONTENT = 6
}
export declare const License_KeyContainer_KeyTypeSchema: GenEnum<License_KeyContainer_KeyType>;
export declare enum License_KeyContainer_SecurityLevel {
    SW_SECURE_CRYPTO = 1,
    SW_SECURE_DECODE = 2,
    HW_SECURE_CRYPTO = 3,
    HW_SECURE_DECODE = 4,
    HW_SECURE_ALL = 5
}
export declare const License_KeyContainer_SecurityLevelSchema: GenEnum<License_KeyContainer_SecurityLevel>;
export type LicenseRequest = Message<"license_protocol.LicenseRequest"> & {
    clientId?: ClientIdentification;
    contentId?: LicenseRequest_ContentIdentification;
    type: LicenseRequest_RequestType;
    requestTime: bigint;
    keyControlNonceDeprecated: Uint8Array;
    protocolVersion: ProtocolVersion;
    keyControlNonce: number;
    encryptedClientId?: EncryptedClientIdentification;
};
export declare const LicenseRequestSchema: GenMessage<LicenseRequest>;
export type LicenseRequest_ContentIdentification = Message<"license_protocol.LicenseRequest.ContentIdentification"> & {
    contentIdVariant: {
        value: LicenseRequest_ContentIdentification_WidevinePsshData;
        case: "widevinePsshData";
    } | {
        value: LicenseRequest_ContentIdentification_WebmKeyId;
        case: "webmKeyId";
    } | {
        value: LicenseRequest_ContentIdentification_ExistingLicense;
        case: "existingLicense";
    } | {
        value: LicenseRequest_ContentIdentification_InitData;
        case: "initData";
    } | {
        case: undefined;
        value?: undefined;
    };
};
export declare const LicenseRequest_ContentIdentificationSchema: GenMessage<LicenseRequest_ContentIdentification>;
export type LicenseRequest_ContentIdentification_WidevinePsshData = Message<"license_protocol.LicenseRequest.ContentIdentification.WidevinePsshData"> & {
    psshData: Uint8Array[];
    licenseType: LicenseType;
    requestId: Uint8Array;
};
export declare const LicenseRequest_ContentIdentification_WidevinePsshDataSchema: GenMessage<LicenseRequest_ContentIdentification_WidevinePsshData>;
export type LicenseRequest_ContentIdentification_WebmKeyId = Message<"license_protocol.LicenseRequest.ContentIdentification.WebmKeyId"> & {
    header: Uint8Array;
    licenseType: LicenseType;
    requestId: Uint8Array;
};
export declare const LicenseRequest_ContentIdentification_WebmKeyIdSchema: GenMessage<LicenseRequest_ContentIdentification_WebmKeyId>;
export type LicenseRequest_ContentIdentification_ExistingLicense = Message<"license_protocol.LicenseRequest.ContentIdentification.ExistingLicense"> & {
    licenseId?: LicenseIdentification;
    secondsSinceStarted: bigint;
    secondsSinceLastPlayed: bigint;
    sessionUsageTableEntry: Uint8Array;
};
export declare const LicenseRequest_ContentIdentification_ExistingLicenseSchema: GenMessage<LicenseRequest_ContentIdentification_ExistingLicense>;
export type LicenseRequest_ContentIdentification_InitData = Message<"license_protocol.LicenseRequest.ContentIdentification.InitData"> & {
    initDataType: LicenseRequest_ContentIdentification_InitData_InitDataType;
    initData: Uint8Array;
    licenseType: LicenseType;
    requestId: Uint8Array;
};
export declare const LicenseRequest_ContentIdentification_InitDataSchema: GenMessage<LicenseRequest_ContentIdentification_InitData>;
export declare enum LicenseRequest_ContentIdentification_InitData_InitDataType {
    CENC = 1,
    WEBM = 2
}
export declare const LicenseRequest_ContentIdentification_InitData_InitDataTypeSchema: GenEnum<LicenseRequest_ContentIdentification_InitData_InitDataType>;
export declare enum LicenseRequest_RequestType {
    NEW = 1,
    RENEWAL = 2,
    RELEASE = 3
}
export declare const LicenseRequest_RequestTypeSchema: GenEnum<LicenseRequest_RequestType>;
export type MetricData = Message<"license_protocol.MetricData"> & {
    stageName: string;
    metricData: MetricData_TypeValue[];
};
export declare const MetricDataSchema: GenMessage<MetricData>;
export type MetricData_TypeValue = Message<"license_protocol.MetricData.TypeValue"> & {
    type: MetricData_MetricType;
    value: bigint;
};
export declare const MetricData_TypeValueSchema: GenMessage<MetricData_TypeValue>;
export declare enum MetricData_MetricType {
    LATENCY = 1,
    TIMESTAMP = 2
}
export declare const MetricData_MetricTypeSchema: GenEnum<MetricData_MetricType>;
export type VersionInfo = Message<"license_protocol.VersionInfo"> & {
    licenseSdkVersion: string;
    licenseServiceVersion: string;
};
export declare const VersionInfoSchema: GenMessage<VersionInfo>;
export type SignedMessage = Message<"license_protocol.SignedMessage"> & {
    type: SignedMessage_MessageType;
    msg: Uint8Array;
    signature: Uint8Array;
    sessionKey: Uint8Array;
    remoteAttestation: Uint8Array;
    metricData: MetricData[];
    serviceVersionInfo?: VersionInfo;
    sessionKeyType: SignedMessage_SessionKeyType;
    oemcryptoCoreMessage: Uint8Array;
};
export declare const SignedMessageSchema: GenMessage<SignedMessage>;
export declare enum SignedMessage_MessageType {
    LICENSE_REQUEST = 1,
    LICENSE = 2,
    ERROR_RESPONSE = 3,
    SERVICE_CERTIFICATE_REQUEST = 4,
    SERVICE_CERTIFICATE = 5,
    SUB_LICENSE = 6,
    CAS_LICENSE_REQUEST = 7,
    CAS_LICENSE = 8,
    EXTERNAL_LICENSE_REQUEST = 9,
    EXTERNAL_LICENSE = 10
}
export declare const SignedMessage_MessageTypeSchema: GenEnum<SignedMessage_MessageType>;
export declare enum SignedMessage_SessionKeyType {
    UNDEFINED = 0,
    WRAPPED_AES_KEY = 1,
    EPHERMERAL_ECC_PUBLIC_KEY = 2
}
export declare const SignedMessage_SessionKeyTypeSchema: GenEnum<SignedMessage_SessionKeyType>;
export type ClientIdentification = Message<"license_protocol.ClientIdentification"> & {
    type: ClientIdentification_TokenType;
    token: Uint8Array;
    clientInfo: ClientIdentification_NameValue[];
    providerClientToken: Uint8Array;
    licenseCounter: number;
    clientCapabilities?: ClientIdentification_ClientCapabilities;
    vmpData: Uint8Array;
    deviceCredentials: ClientIdentification_ClientCredentials[];
};
export declare const ClientIdentificationSchema: GenMessage<ClientIdentification>;
export type ClientIdentification_NameValue = Message<"license_protocol.ClientIdentification.NameValue"> & {
    name: string;
    value: string;
};
export declare const ClientIdentification_NameValueSchema: GenMessage<ClientIdentification_NameValue>;
export type ClientIdentification_ClientCapabilities = Message<"license_protocol.ClientIdentification.ClientCapabilities"> & {
    clientToken: boolean;
    sessionToken: boolean;
    videoResolutionConstraints: boolean;
    maxHdcpVersion: ClientIdentification_ClientCapabilities_HdcpVersion;
    oemCryptoApiVersion: number;
    antiRollbackUsageTable: boolean;
    srmVersion: number;
    canUpdateSrm: boolean;
    supportedCertificateKeyType: ClientIdentification_ClientCapabilities_CertificateKeyType[];
    analogOutputCapabilities: ClientIdentification_ClientCapabilities_AnalogOutputCapabilities;
    canDisableAnalogOutput: boolean;
    resourceRatingTier: number;
};
export declare const ClientIdentification_ClientCapabilitiesSchema: GenMessage<ClientIdentification_ClientCapabilities>;
export declare enum ClientIdentification_ClientCapabilities_HdcpVersion {
    HDCP_NONE = 0,
    HDCP_V1 = 1,
    HDCP_V2 = 2,
    HDCP_V2_1 = 3,
    HDCP_V2_2 = 4,
    HDCP_V2_3 = 5,
    HDCP_NO_DIGITAL_OUTPUT = 255
}
export declare const ClientIdentification_ClientCapabilities_HdcpVersionSchema: GenEnum<ClientIdentification_ClientCapabilities_HdcpVersion>;
export declare enum ClientIdentification_ClientCapabilities_CertificateKeyType {
    RSA_2048 = 0,
    RSA_3072 = 1,
    ECC_SECP256R1 = 2,
    ECC_SECP384R1 = 3,
    ECC_SECP521R1 = 4
}
export declare const ClientIdentification_ClientCapabilities_CertificateKeyTypeSchema: GenEnum<ClientIdentification_ClientCapabilities_CertificateKeyType>;
export declare enum ClientIdentification_ClientCapabilities_AnalogOutputCapabilities {
    ANALOG_OUTPUT_UNKNOWN = 0,
    ANALOG_OUTPUT_NONE = 1,
    ANALOG_OUTPUT_SUPPORTED = 2,
    ANALOG_OUTPUT_SUPPORTS_CGMS_A = 3
}
export declare const ClientIdentification_ClientCapabilities_AnalogOutputCapabilitiesSchema: GenEnum<ClientIdentification_ClientCapabilities_AnalogOutputCapabilities>;
export type ClientIdentification_ClientCredentials = Message<"license_protocol.ClientIdentification.ClientCredentials"> & {
    type: ClientIdentification_TokenType;
    token: Uint8Array;
};
export declare const ClientIdentification_ClientCredentialsSchema: GenMessage<ClientIdentification_ClientCredentials>;
export declare enum ClientIdentification_TokenType {
    KEYBOX = 0,
    DRM_DEVICE_CERTIFICATE = 1,
    REMOTE_ATTESTATION_CERTIFICATE = 2,
    OEM_DEVICE_CERTIFICATE = 3
}
export declare const ClientIdentification_TokenTypeSchema: GenEnum<ClientIdentification_TokenType>;
export type EncryptedClientIdentification = Message<"license_protocol.EncryptedClientIdentification"> & {
    providerId: string;
    serviceCertificateSerialNumber: Uint8Array;
    encryptedClientId: Uint8Array;
    encryptedClientIdIv: Uint8Array;
    encryptedPrivacyKey: Uint8Array;
};
export declare const EncryptedClientIdentificationSchema: GenMessage<EncryptedClientIdentification>;
export type DrmCertificate = Message<"license_protocol.DrmCertificate"> & {
    type: DrmCertificate_Type;
    serialNumber: Uint8Array;
    creationTimeSeconds: number;
    expirationTimeSeconds: number;
    publicKey: Uint8Array;
    systemId: number;
    testDeviceDeprecated: boolean;
    providerId: string;
    serviceTypes: DrmCertificate_ServiceType[];
    algorithm: DrmCertificate_Algorithm;
    rotId: Uint8Array;
    encryptionKey?: DrmCertificate_EncryptionKey;
};
export declare const DrmCertificateSchema: GenMessage<DrmCertificate>;
export type DrmCertificate_EncryptionKey = Message<"license_protocol.DrmCertificate.EncryptionKey"> & {
    publicKey: Uint8Array;
    algorithm: DrmCertificate_Algorithm;
};
export declare const DrmCertificate_EncryptionKeySchema: GenMessage<DrmCertificate_EncryptionKey>;
export declare enum DrmCertificate_Type {
    ROOT = 0,
    DEVICE_MODEL = 1,
    DEVICE = 2,
    SERVICE = 3,
    PROVISIONER = 4
}
export declare const DrmCertificate_TypeSchema: GenEnum<DrmCertificate_Type>;
export declare enum DrmCertificate_ServiceType {
    UNKNOWN_SERVICE_TYPE = 0,
    LICENSE_SERVER_SDK = 1,
    LICENSE_SERVER_PROXY_SDK = 2,
    PROVISIONING_SDK = 3,
    CAS_PROXY_SDK = 4
}
export declare const DrmCertificate_ServiceTypeSchema: GenEnum<DrmCertificate_ServiceType>;
export declare enum DrmCertificate_Algorithm {
    UNKNOWN_ALGORITHM = 0,
    RSA = 1,
    ECC_SECP256R1 = 2,
    ECC_SECP384R1 = 3,
    ECC_SECP521R1 = 4
}
export declare const DrmCertificate_AlgorithmSchema: GenEnum<DrmCertificate_Algorithm>;
export type SignedDrmCertificate = Message<"license_protocol.SignedDrmCertificate"> & {
    drmCertificate: Uint8Array;
    signature: Uint8Array;
    signer?: SignedDrmCertificate;
    hashAlgorithm: HashAlgorithmProto;
};
export declare const SignedDrmCertificateSchema: GenMessage<SignedDrmCertificate>;
export type WidevinePsshData = Message<"license_protocol.WidevinePsshData"> & {
    keyIds: Uint8Array[];
    contentId: Uint8Array;
    cryptoPeriodIndex: number;
    protectionScheme: number;
    cryptoPeriodSeconds: number;
    type: WidevinePsshData_Type;
    keySequence: number;
    groupIds: Uint8Array[];
    entitledKeys: WidevinePsshData_EntitledKey[];
    videoFeature: string;
    algorithm: WidevinePsshData_Algorithm;
    provider: string;
    trackType: string;
    policy: string;
    groupedLicense: Uint8Array;
};
export declare const WidevinePsshDataSchema: GenMessage<WidevinePsshData>;
export type WidevinePsshData_EntitledKey = Message<"license_protocol.WidevinePsshData.EntitledKey"> & {
    entitlementKeyId: Uint8Array;
    keyId: Uint8Array;
    key: Uint8Array;
    iv: Uint8Array;
    entitlementKeySizeBytes: number;
};
export declare const WidevinePsshData_EntitledKeySchema: GenMessage<WidevinePsshData_EntitledKey>;
export declare enum WidevinePsshData_Type {
    SINGLE = 0,
    ENTITLEMENT = 1,
    ENTITLED_KEY = 2
}
export declare const WidevinePsshData_TypeSchema: GenEnum<WidevinePsshData_Type>;
export declare enum WidevinePsshData_Algorithm {
    UNENCRYPTED = 0,
    AESCTR = 1
}
export declare const WidevinePsshData_AlgorithmSchema: GenEnum<WidevinePsshData_Algorithm>;
export type FileHashes = Message<"license_protocol.FileHashes"> & {
    signer: Uint8Array;
    signatures: FileHashes_Signature[];
};
export declare const FileHashesSchema: GenMessage<FileHashes>;
export type FileHashes_Signature = Message<"license_protocol.FileHashes.Signature"> & {
    filename: string;
    testSigning: boolean;
    SHA512Hash: Uint8Array;
    mainExe: boolean;
    signature: Uint8Array;
};
export declare const FileHashes_SignatureSchema: GenMessage<FileHashes_Signature>;
export declare enum LicenseType {
    STREAMING = 1,
    OFFLINE = 2,
    AUTOMATIC = 3
}
export declare const LicenseTypeSchema: GenEnum<LicenseType>;
export declare enum PlatformVerificationStatus {
    PLATFORM_UNVERIFIED = 0,
    PLATFORM_TAMPERED = 1,
    PLATFORM_SOFTWARE_VERIFIED = 2,
    PLATFORM_HARDWARE_VERIFIED = 3,
    PLATFORM_NO_VERIFICATION = 4,
    PLATFORM_SECURE_STORAGE_SOFTWARE_VERIFIED = 5
}
export declare const PlatformVerificationStatusSchema: GenEnum<PlatformVerificationStatus>;
export declare enum ProtocolVersion {
    VERSION_2_0 = 20,
    VERSION_2_1 = 21,
    VERSION_2_2 = 22
}
export declare const ProtocolVersionSchema: GenEnum<ProtocolVersion>;
export declare enum HashAlgorithmProto {
    HASH_ALGORITHM_UNSPECIFIED = 0,
    HASH_ALGORITHM_SHA_1 = 1,
    HASH_ALGORITHM_SHA_256 = 2,
    HASH_ALGORITHM_SHA_384 = 3
}
export declare const HashAlgorithmProtoSchema: GenEnum<HashAlgorithmProto>;
