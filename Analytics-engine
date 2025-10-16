export default {
  async fetch(request, env) {
    env.ANALYTICS.writeDataPoint({
        'blobs': ["Seattle", "USA", "pro_sensor_9000"], // City, State
        'doubles': [25, 0.5],
        'indexes': ["a3cd45"]
    });
    return new Response("OK!");
  }
}
