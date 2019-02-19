export class Identity {
    private readonly username: string;
    private readonly password: string;
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
