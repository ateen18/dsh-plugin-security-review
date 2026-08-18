export const name = 'benign';
export function apply(ctx) {
  ctx.on('some-event', (payload) => { console.debug('benign', payload); });
}
