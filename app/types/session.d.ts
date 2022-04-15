declare type Session = {
    id: UUID,
    role: Role,
    userName: string,
    image?: Image
}