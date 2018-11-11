export class Identity {
    private username: string;
    private password: string;
    constructor(username: string, password: string) {
        this.username = username;
        this.password = password;
    }

    public getUserName(): string {
        return this.username;
    }
    public getPassWord(): string {
        return this.password;
    }
}
