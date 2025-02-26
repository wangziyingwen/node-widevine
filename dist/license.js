import { AES_CMAC } from "./cmac.js";
import forge from "node-forge";
import { ClientIdentificationSchema, DrmCertificateSchema, EncryptedClientIdentificationSchema, LicenseRequest_ContentIdentification_WidevinePsshDataSchema, LicenseRequest_ContentIdentificationSchema, LicenseRequest_RequestType, LicenseRequestSchema, LicenseSchema, LicenseType, ProtocolVersion, SignedDrmCertificateSchema, SignedMessage_MessageType, SignedMessageSchema, WidevinePsshDataSchema } from "./license_protocol_pb.js";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
const WIDEVINE_SYSTEM_ID = new Uint8Array([0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed]);
const WIDEVINE_ROOT_PUBLIC_KEY = new Uint8Array([
    0x30, 0x82, 0x01, 0x8a, 0x02, 0x82, 0x01, 0x81, 0x00, 0xb4, 0xfe, 0x39, 0xc3, 0x65, 0x90, 0x03, 0xdb, 0x3c, 0x11, 0x97, 0x09, 0xe8, 0x68, 0xcd,
    0xf2, 0xc3, 0x5e, 0x9b, 0xf2, 0xe7, 0x4d, 0x23, 0xb1, 0x10, 0xdb, 0x87, 0x65, 0xdf, 0xdc, 0xfb, 0x9f, 0x35, 0xa0, 0x57, 0x03, 0x53, 0x4c, 0xf6,
    0x6d, 0x35, 0x7d, 0xa6, 0x78, 0xdb, 0xb3, 0x36, 0xd2, 0x3f, 0x9c, 0x40, 0xa9, 0x95, 0x26, 0x72, 0x7f, 0xb8, 0xbe, 0x66, 0xdf, 0xc5, 0x21, 0x98,
    0x78, 0x15, 0x16, 0x68, 0x5d, 0x2f, 0x46, 0x0e, 0x43, 0xcb, 0x8a, 0x84, 0x39, 0xab, 0xfb, 0xb0, 0x35, 0x80, 0x22, 0xbe, 0x34, 0x23, 0x8b, 0xab,
    0x53, 0x5b, 0x72, 0xec, 0x4b, 0xb5, 0x48, 0x69, 0x53, 0x3e, 0x47, 0x5f, 0xfd, 0x09, 0xfd, 0xa7, 0x76, 0x13, 0x8f, 0x0f, 0x92, 0xd6, 0x4c, 0xdf,
    0xae, 0x76, 0xa9, 0xba, 0xd9, 0x22, 0x10, 0xa9, 0x9d, 0x71, 0x45, 0xd6, 0xd7, 0xe1, 0x19, 0x25, 0x85, 0x9c, 0x53, 0x9a, 0x97, 0xeb, 0x84, 0xd7,
    0xcc, 0xa8, 0x88, 0x82, 0x20, 0x70, 0x26, 0x20, 0xfd, 0x7e, 0x40, 0x50, 0x27, 0xe2, 0x25, 0x93, 0x6f, 0xbc, 0x3e, 0x72, 0xa0, 0xfa, 0xc1, 0xbd,
    0x29, 0xb4, 0x4d, 0x82, 0x5c, 0xc1, 0xb4, 0xcb, 0x9c, 0x72, 0x7e, 0xb0, 0xe9, 0x8a, 0x17, 0x3e, 0x19, 0x63, 0xfc, 0xfd, 0x82, 0x48, 0x2b, 0xb7,
    0xb2, 0x33, 0xb9, 0x7d, 0xec, 0x4b, 0xba, 0x89, 0x1f, 0x27, 0xb8, 0x9b, 0x88, 0x48, 0x84, 0xaa, 0x18, 0x92, 0x0e, 0x65, 0xf5, 0xc8, 0x6c, 0x11,
    0xff, 0x6b, 0x36, 0xe4, 0x74, 0x34, 0xca, 0x8c, 0x33, 0xb1, 0xf9, 0xb8, 0x8e, 0xb4, 0xe6, 0x12, 0xe0, 0x02, 0x98, 0x79, 0x52, 0x5e, 0x45, 0x33,
    0xff, 0x11, 0xdc, 0xeb, 0xc3, 0x53, 0xba, 0x7c, 0x60, 0x1a, 0x11, 0x3d, 0x00, 0xfb, 0xd2, 0xb7, 0xaa, 0x30, 0xfa, 0x4f, 0x5e, 0x48, 0x77, 0x5b,
    0x17, 0xdc, 0x75, 0xef, 0x6f, 0xd2, 0x19, 0x6d, 0xdc, 0xbe, 0x7f, 0xb0, 0x78, 0x8f, 0xdc, 0x82, 0x60, 0x4c, 0xbf, 0xe4, 0x29, 0x06, 0x5e, 0x69,
    0x8c, 0x39, 0x13, 0xad, 0x14, 0x25, 0xed, 0x19, 0xb2, 0xf2, 0x9f, 0x01, 0x82, 0x0d, 0x56, 0x44, 0x88, 0xc8, 0x35, 0xec, 0x1f, 0x11, 0xb3, 0x24,
    0xe0, 0x59, 0x0d, 0x37, 0xe4, 0x47, 0x3c, 0xea, 0x4b, 0x7f, 0x97, 0x31, 0x1c, 0x81, 0x7c, 0x94, 0x8a, 0x4c, 0x7d, 0x68, 0x15, 0x84, 0xff, 0xa5,
    0x08, 0xfd, 0x18, 0xe7, 0xe7, 0x2b, 0xe4, 0x47, 0x27, 0x12, 0x11, 0xb8, 0x23, 0xec, 0x58, 0x93, 0x3c, 0xac, 0x12, 0xd2, 0x88, 0x6d, 0x41, 0x3d,
    0xc5, 0xfe, 0x1c, 0xdc, 0xb9, 0xf8, 0xd4, 0x51, 0x3e, 0x07, 0xe5, 0x03, 0x6f, 0xa7, 0x12, 0xe8, 0x12, 0xf7, 0xb5, 0xce, 0xa6, 0x96, 0x55, 0x3f,
    0x78, 0xb4, 0x64, 0x82, 0x50, 0xd2, 0x33, 0x5f, 0x91, 0x02, 0x03, 0x01, 0x00, 0x01
]);
export const SERVICE_CERTIFICATE_CHALLENGE = new Uint8Array([0x08, 0x04]);
const COMMON_SERVICE_CERTIFICATE = new Uint8Array([
    0x08, 0x05, 0x12, 0xc7, 0x05, 0x0a, 0xc1, 0x02, 0x08, 0x03, 0x12, 0x10, 0x17, 0x05, 0xb9, 0x17, 0xcc, 0x12, 0x04, 0x86, 0x8b, 0x06, 0x33, 0x3a,
    0x2f, 0x77, 0x2a, 0x8c, 0x18, 0x82, 0xb4, 0x82, 0x92, 0x05, 0x22, 0x8e, 0x02, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x99, 0xed,
    0x5b, 0x3b, 0x32, 0x7d, 0xab, 0x5e, 0x24, 0xef, 0xc3, 0xb6, 0x2a, 0x95, 0xb5, 0x98, 0x52, 0x0a, 0xd5, 0xbc, 0xcb, 0x37, 0x50, 0x3e, 0x06, 0x45,
    0xb8, 0x14, 0xd8, 0x76, 0xb8, 0xdf, 0x40, 0x51, 0x04, 0x41, 0xad, 0x8c, 0xe3, 0xad, 0xb1, 0x1b, 0xb8, 0x8c, 0x4e, 0x72, 0x5a, 0x5e, 0x4a, 0x9e,
    0x07, 0x95, 0x29, 0x1d, 0x58, 0x58, 0x40, 0x23, 0xa7, 0xe1, 0xaf, 0x0e, 0x38, 0xa9, 0x12, 0x79, 0x39, 0x30, 0x08, 0x61, 0x0b, 0x6f, 0x15, 0x8c,
    0x87, 0x8c, 0x7e, 0x21, 0xbf, 0xfb, 0xfe, 0xea, 0x77, 0xe1, 0x01, 0x9e, 0x1e, 0x57, 0x81, 0xe8, 0xa4, 0x5f, 0x46, 0x26, 0x3d, 0x14, 0xe6, 0x0e,
    0x80, 0x58, 0xa8, 0x60, 0x7a, 0xdc, 0xe0, 0x4f, 0xac, 0x84, 0x57, 0xb1, 0x37, 0xa8, 0xd6, 0x7c, 0xcd, 0xeb, 0x33, 0x70, 0x5d, 0x98, 0x3a, 0x21,
    0xfb, 0x4e, 0xec, 0xbd, 0x4a, 0x10, 0xca, 0x47, 0x49, 0x0c, 0xa4, 0x7e, 0xaa, 0x5d, 0x43, 0x82, 0x18, 0xdd, 0xba, 0xf1, 0xca, 0xde, 0x33, 0x92,
    0xf1, 0x3d, 0x6f, 0xfb, 0x64, 0x42, 0xfd, 0x31, 0xe1, 0xbf, 0x40, 0xb0, 0xc6, 0x04, 0xd1, 0xc4, 0xba, 0x4c, 0x95, 0x20, 0xa4, 0xbf, 0x97, 0xee,
    0xbd, 0x60, 0x92, 0x9a, 0xfc, 0xee, 0xf5, 0x5b, 0xba, 0xf5, 0x64, 0xe2, 0xd0, 0xe7, 0x6c, 0xd7, 0xc5, 0x5c, 0x73, 0xa0, 0x82, 0xb9, 0x96, 0x12,
    0x0b, 0x83, 0x59, 0xed, 0xce, 0x24, 0x70, 0x70, 0x82, 0x68, 0x0d, 0x6f, 0x67, 0xc6, 0xd8, 0x2c, 0x4a, 0xc5, 0xf3, 0x13, 0x44, 0x90, 0xa7, 0x4e,
    0xec, 0x37, 0xaf, 0x4b, 0x2f, 0x01, 0x0c, 0x59, 0xe8, 0x28, 0x43, 0xe2, 0x58, 0x2f, 0x0b, 0x6b, 0x9f, 0x5d, 0xb0, 0xfc, 0x5e, 0x6e, 0xdf, 0x64,
    0xfb, 0xd3, 0x08, 0xb4, 0x71, 0x1b, 0xcf, 0x12, 0x50, 0x01, 0x9c, 0x9f, 0x5a, 0x09, 0x02, 0x03, 0x01, 0x00, 0x01, 0x3a, 0x14, 0x6c, 0x69, 0x63,
    0x65, 0x6e, 0x73, 0x65, 0x2e, 0x77, 0x69, 0x64, 0x65, 0x76, 0x69, 0x6e, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x12, 0x80, 0x03, 0xae, 0x34, 0x73, 0x14,
    0xb5, 0xa8, 0x35, 0x29, 0x7f, 0x27, 0x13, 0x88, 0xfb, 0x7b, 0xb8, 0xcb, 0x52, 0x77, 0xd2, 0x49, 0x82, 0x3c, 0xdd, 0xd1, 0xda, 0x30, 0xb9, 0x33,
    0x39, 0x51, 0x1e, 0xb3, 0xcc, 0xbd, 0xea, 0x04, 0xb9, 0x44, 0xb9, 0x27, 0xc1, 0x21, 0x34, 0x6e, 0xfd, 0xbd, 0xea, 0xc9, 0xd4, 0x13, 0x91, 0x7e,
    0x6e, 0xc1, 0x76, 0xa1, 0x04, 0x38, 0x46, 0x0a, 0x50, 0x3b, 0xc1, 0x95, 0x2b, 0x9b, 0xa4, 0xe4, 0xce, 0x0f, 0xc4, 0xbf, 0xc2, 0x0a, 0x98, 0x08,
    0xaa, 0xaf, 0x4b, 0xfc, 0xd1, 0x9c, 0x1d, 0xcf, 0xcd, 0xf5, 0x74, 0xcc, 0xac, 0x28, 0xd1, 0xb4, 0x10, 0x41, 0x6c, 0xf9, 0xde, 0x88, 0x04, 0x30,
    0x1c, 0xbd, 0xb3, 0x34, 0xca, 0xfc, 0xd0, 0xd4, 0x09, 0x78, 0x42, 0x3a, 0x64, 0x2e, 0x54, 0x61, 0x3d, 0xf0, 0xaf, 0xcf, 0x96, 0xca, 0x4a, 0x92,
    0x49, 0xd8, 0x55, 0xe4, 0x2b, 0x3a, 0x70, 0x3e, 0xf1, 0x76, 0x7f, 0x6a, 0x9b, 0xd3, 0x6d, 0x6b, 0xf8, 0x2b, 0xe7, 0x6b, 0xbf, 0x0c, 0xba, 0x4f,
    0xde, 0x59, 0xd2, 0xab, 0xcc, 0x76, 0xfe, 0xb6, 0x42, 0x47, 0xb8, 0x5c, 0x43, 0x1f, 0xbc, 0xa5, 0x22, 0x66, 0xb6, 0x19, 0xfc, 0x36, 0x97, 0x95,
    0x43, 0xfc, 0xa9, 0xcb, 0xbd, 0xbb, 0xfa, 0xfa, 0x0e, 0x1a, 0x55, 0xe7, 0x55, 0xa3, 0xc7, 0xbc, 0xe6, 0x55, 0xf9, 0x64, 0x6f, 0x58, 0x2a, 0xb9,
    0xcf, 0x70, 0xaa, 0x08, 0xb9, 0x79, 0xf8, 0x67, 0xf6, 0x3a, 0x0b, 0x2b, 0x7f, 0xdb, 0x36, 0x2c, 0x5b, 0xc4, 0xec, 0xd5, 0x55, 0xd8, 0x5b, 0xca,
    0xa9, 0xc5, 0x93, 0xc3, 0x83, 0xc8, 0x57, 0xd4, 0x9d, 0xaa, 0xb7, 0x7e, 0x40, 0xb7, 0x85, 0x1d, 0xdf, 0xd2, 0x49, 0x98, 0x80, 0x8e, 0x35, 0xb2,
    0x58, 0xe7, 0x5d, 0x78, 0xea, 0xc0, 0xca, 0x16, 0xf7, 0x04, 0x73, 0x04, 0xc2, 0x0d, 0x93, 0xed, 0xe4, 0xe8, 0xff, 0x1c, 0x6f, 0x17, 0xe6, 0x24,
    0x3e, 0x3f, 0x3d, 0xa8, 0xfc, 0x17, 0x09, 0x87, 0x0e, 0xc4, 0x5f, 0xba, 0x82, 0x3a, 0x26, 0x3f, 0x0c, 0xef, 0xa1, 0xf7, 0x09, 0x3b, 0x19, 0x09,
    0x92, 0x83, 0x26, 0x33, 0x37, 0x05, 0x04, 0x3a, 0x29, 0xbd, 0xa6, 0xf9, 0xb4, 0x34, 0x2c, 0xc8, 0xdf, 0x54, 0x3c, 0xb1, 0xa1, 0x18, 0x2f, 0x7c,
    0x5f, 0xff, 0x33, 0xf1, 0x04, 0x90, 0xfa, 0xca, 0x5b, 0x25, 0x36, 0x0b, 0x76, 0x01, 0x5e, 0x9c, 0x5a, 0x06, 0xab, 0x8e, 0xe0, 0x2f, 0x00, 0xd2,
    0xe8, 0xd5, 0x98, 0x61, 0x04, 0xaa, 0xcc, 0x4d, 0xd4, 0x75, 0xfd, 0x96, 0xee, 0x9c, 0xe4, 0xe3, 0x26, 0xf2, 0x1b, 0x83, 0xc7, 0x05, 0x85, 0x77,
    0xb3, 0x87, 0x32, 0xcd, 0xda, 0xbc, 0x6a, 0x6b, 0xed, 0x13, 0xfb, 0x0d, 0x49, 0xd3, 0x8a, 0x45, 0xeb, 0x87, 0xa5, 0xf4
]);
export class Session {
    _devicePrivateKey;
    _identifierBlob;
    _pssh;
    _rawLicenseRequest;
    _serviceCertificate;
    constructor(contentDecryptionModule, pssh) {
        this._devicePrivateKey = forge.pki.privateKeyFromPem(contentDecryptionModule.privateKey.toString("binary"));
        this._identifierBlob = fromBinary(ClientIdentificationSchema, contentDecryptionModule.identifierBlob);
        this._pssh = pssh;
    }
    async setDefaultServiceCertificate() {
        await this.setServiceCertificate(Buffer.from(COMMON_SERVICE_CERTIFICATE));
    }
    async setServiceCertificateFromMessage(rawSignedMessage) {
        const signedMessage = fromBinary(SignedMessageSchema, rawSignedMessage);
        if (!signedMessage.msg) {
            throw new Error("the service certificate message does not contain a message");
        }
        await this.setServiceCertificate(Buffer.from(signedMessage.msg));
    }
    async setServiceCertificate(serviceCertificate) {
        const signedServiceCertificate = fromBinary(SignedDrmCertificateSchema, serviceCertificate);
        if (!(await this._verifyServiceCertificate(signedServiceCertificate))) {
            throw new Error("Service certificate is not signed by the Widevine root certificate");
        }
        this._serviceCertificate = signedServiceCertificate;
    }
    createLicenseRequest(licenseType = LicenseType.STREAMING, android = false) {
        if (!this._pssh.subarray(12, 28).equals(Buffer.from(WIDEVINE_SYSTEM_ID))) {
            throw new Error("the pssh is not an actuall pssh");
        }
        const pssh = this._parsePSSH(this._pssh);
        if (!pssh) {
            throw new Error("pssh is invalid");
        }
        const licenseRequest = create(LicenseRequestSchema, {
            type: LicenseRequest_RequestType.NEW,
            contentId: create(LicenseRequest_ContentIdentificationSchema, {
                contentIdVariant: {
                    case: "widevinePsshData",
                    value: create(LicenseRequest_ContentIdentification_WidevinePsshDataSchema, {
                        psshData: [this._pssh.subarray(32)],
                        licenseType: licenseType,
                        requestId: android ? this._generateAndroidIdentifier() : this._generateGenericIdentifier()
                    })
                }
            }),
            requestTime: BigInt(Date.now()) / BigInt(1000),
            protocolVersion: ProtocolVersion.VERSION_2_1,
            keyControlNonce: Math.floor(Math.random() * 2 ** 31)
        });
        if (this._serviceCertificate) {
            const encryptedClientIdentification = this._encryptClientIdentification(this._identifierBlob, this._serviceCertificate);
            licenseRequest.encryptedClientId = encryptedClientIdentification;
        }
        else {
            licenseRequest.clientId = this._identifierBlob;
        }
        this._rawLicenseRequest = Buffer.from(toBinary(LicenseRequestSchema, licenseRequest));
        const pss = forge.pss.create({ md: forge.md.sha1.create(), mgf: forge.mgf.mgf1.create(forge.md.sha1.create()), saltLength: 20 });
        const md = forge.md.sha1.create();
        md.update(this._rawLicenseRequest.toString("binary"), "raw");
        const signature = Buffer.from(this._devicePrivateKey.sign(md, pss), "binary");
        const signedLicenseRequest = create(SignedMessageSchema, {
            type: SignedMessage_MessageType.LICENSE_REQUEST,
            msg: this._rawLicenseRequest,
            signature: signature
        });
        return Buffer.from(toBinary(SignedMessageSchema, signedLicenseRequest));
    }
    parseLicense(rawLicense) {
        if (!this._rawLicenseRequest) {
            throw new Error("please request a license first");
        }
        const signedLicense = fromBinary(SignedMessageSchema, rawLicense);
        if (!signedLicense.sessionKey) {
            throw new Error("the license does not contain a session key");
        }
        if (!signedLicense.msg) {
            throw new Error("the license does not contain a message");
        }
        if (!signedLicense.signature) {
            throw new Error("the license does not contain a signature");
        }
        const sessionKey = this._devicePrivateKey.decrypt(Buffer.from(signedLicense.sessionKey).toString("binary"), "RSA-OAEP", {
            md: forge.md.sha1.create()
        });
        const cmac = new AES_CMAC(Buffer.from(sessionKey, "binary"));
        const encKeyBase = Buffer.concat([
            Buffer.from("ENCRYPTION"),
            Buffer.from("\x00", "ascii"),
            this._rawLicenseRequest,
            Buffer.from("\x00\x00\x00\x80", "ascii")
        ]);
        const authKeyBase = Buffer.concat([
            Buffer.from("AUTHENTICATION"),
            Buffer.from("\x00", "ascii"),
            this._rawLicenseRequest,
            Buffer.from("\x00\x00\x02\x00", "ascii")
        ]);
        const encKey = cmac.calculate(Buffer.concat([Buffer.from("\x01"), encKeyBase]));
        const serverKey = Buffer.concat([
            cmac.calculate(Buffer.concat([Buffer.from("\x01"), authKeyBase])),
            cmac.calculate(Buffer.concat([Buffer.from("\x02"), authKeyBase]))
        ]);
        const hmac = forge.hmac.create();
        hmac.start(forge.md.sha256.create(), serverKey.toString("binary"));
        hmac.update(Buffer.from(signedLicense.msg).toString("binary"));
        const calculatedSignature = Buffer.from(hmac.digest().data, "binary");
        if (!calculatedSignature.equals(signedLicense.signature)) {
            throw new Error("signatures do not match");
        }
        const license = fromBinary(LicenseSchema, signedLicense.msg);
        const keyContainers = license.key.map((keyContainer) => {
            if (keyContainer.type && keyContainer.key && keyContainer.iv) {
                const keyId = keyContainer.id ? Buffer.from(keyContainer.id).toString("hex") : "00000000000000000000000000000000";
                const decipher = forge.cipher.createDecipher("AES-CBC", encKey.toString("binary"));
                decipher.start({ iv: Buffer.from(keyContainer.iv).toString("binary") });
                decipher.update(forge.util.createBuffer(keyContainer.key));
                decipher.finish();
                const decryptedKey = Buffer.from(decipher.output.data, "binary");
                const key = {
                    kid: keyId,
                    key: decryptedKey.toString("hex")
                };
                return key;
            }
        });
        if (keyContainers.filter((container) => !!container).length < 1) {
            throw new Error("there was not a single valid key in the response");
        }
        return keyContainers;
    }
    _encryptClientIdentification(clientIdentification, signedServiceCertificate) {
        if (!signedServiceCertificate.drmCertificate) {
            throw new Error("the service certificate does not contain an actual certificate");
        }
        const serviceCertificate = fromBinary(DrmCertificateSchema, signedServiceCertificate.drmCertificate);
        if (!serviceCertificate.publicKey) {
            throw new Error("the service certificate does not contain a public key");
        }
        const key = forge.random.getBytesSync(16);
        const iv = forge.random.getBytesSync(16);
        const cipher = forge.cipher.createCipher("AES-CBC", key);
        cipher.start({ iv: iv });
        cipher.update(forge.util.createBuffer(toBinary(ClientIdentificationSchema, clientIdentification)));
        cipher.finish();
        const rawEncryptedClientIdentification = Buffer.from(cipher.output.data, "binary");
        const publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(Buffer.from(serviceCertificate.publicKey).toString("binary")));
        const encryptedKey = publicKey.encrypt(key, "RSA-OAEP", { md: forge.md.sha1.create() });
        const encryptedClientIdentification = create(EncryptedClientIdentificationSchema, {
            encryptedClientId: rawEncryptedClientIdentification,
            encryptedClientIdIv: Buffer.from(iv, "binary"),
            encryptedPrivacyKey: Buffer.from(encryptedKey, "binary"),
            providerId: serviceCertificate.providerId,
            serviceCertificateSerialNumber: serviceCertificate.serialNumber
        });
        return encryptedClientIdentification;
    }
    async _verifyServiceCertificate(signedServiceCertificate) {
        if (!signedServiceCertificate.drmCertificate) {
            throw new Error("the service certificate does not contain an actual certificate");
        }
        if (!signedServiceCertificate.signature) {
            throw new Error("the service certificate does not contain a signature");
        }
        const publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(Buffer.from(WIDEVINE_ROOT_PUBLIC_KEY).toString("binary")));
        const pss = forge.pss.create({ md: forge.md.sha1.create(), mgf: forge.mgf.mgf1.create(forge.md.sha1.create()), saltLength: 20 });
        const sha1 = forge.md.sha1.create();
        sha1.update(Buffer.from(signedServiceCertificate.drmCertificate).toString("binary"), "raw");
        return publicKey.verify(sha1.digest().bytes(), Buffer.from(signedServiceCertificate.signature).toString("binary"), pss);
    }
    _parsePSSH(pssh) {
        try {
            return fromBinary(WidevinePsshDataSchema, pssh.subarray(32));
        }
        catch {
            return null;
        }
    }
    _generateAndroidIdentifier() {
        return Buffer.from(`${forge.util.bytesToHex(forge.random.getBytesSync(8))}${"01"}${"00000000000000"}`);
    }
    _generateGenericIdentifier() {
        return Buffer.from(forge.random.getBytesSync(16), "binary");
    }
    get pssh() {
        return this._pssh;
    }
}
//# sourceMappingURL=license.js.map