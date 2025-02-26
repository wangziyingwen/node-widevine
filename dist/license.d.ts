import { LicenseType } from "./license_protocol_pb.js";
export declare const SERVICE_CERTIFICATE_CHALLENGE: Uint8Array;
export type KeyContainer = {
    kid: string;
    key: string;
};
export type ContentDecryptionModule = {
    privateKey: Buffer;
    identifierBlob: Buffer;
};
export declare class Session {
    private _devicePrivateKey;
    private _identifierBlob;
    private _pssh;
    private _rawLicenseRequest?;
    private _serviceCertificate?;
    constructor(contentDecryptionModule: ContentDecryptionModule, pssh: Buffer);
    setDefaultServiceCertificate(): Promise<void>;
    setServiceCertificateFromMessage(rawSignedMessage: Buffer): Promise<void>;
    setServiceCertificate(serviceCertificate: Buffer): Promise<void>;
    createLicenseRequest(licenseType?: LicenseType, android?: boolean): Buffer;
    parseLicense(rawLicense: Buffer): (KeyContainer | undefined)[];
    private _encryptClientIdentification;
    private _verifyServiceCertificate;
    private _parsePSSH;
    private _generateAndroidIdentifier;
    private _generateGenericIdentifier;
    get pssh(): Buffer;
}
