export interface Service {
    handlers: {
        [name: string]: RequestHandler;
    }
}

export type RequestHandler = (...args: any[]) => any;
