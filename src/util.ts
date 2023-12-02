
export function primitiveDeepClone<T> (object: T): T {
    return JSON.parse(JSON.stringify(object));
}