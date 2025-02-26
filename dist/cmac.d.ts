export declare class AES_CMAC {
    private readonly BLOCK_SIZE;
    private readonly XOR_RIGHT;
    private readonly EMPTY_BLOCK_SIZE_BUFFER;
    private _key;
    private _subkeys;
    constructor(key: Buffer);
    calculate(message: Buffer): Buffer;
    private _generateSubkeys;
    private _getBlockCount;
    private _aes;
    private _getLastBlock;
    private _padding;
    private _bitShiftLeft;
    private _xor;
}
