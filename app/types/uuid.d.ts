declare type UUID = string & {
    readonly _isUUID: unique symbol
};