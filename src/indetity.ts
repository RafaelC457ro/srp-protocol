export class Identity {
    private username: string;
    private password: string;
    constructor(username: string, password: string) {
        this.username = username;
        this.password = password;
    }

    getUserName(): string {
        return this.username;
    }
    getPassWord(): string {
        return this.password;
    }
}
