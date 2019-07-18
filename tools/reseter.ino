uint8_t received_data[128];
uint8_t received = 0;
uint8_t received_byte;
const uint8_t BEG_CHAR = '!';
const uint8_t END_CHAR = '$';
const uint8_t MAX_SZ = 4;
const uint8_t RELEY_NUM = 1;
const uint8_t RELEY_STATE = 2;

const uint8_t RELEYS[] = {3, 2, 4, 5};

void setup() {
  // Prepare serial
  Serial.begin(9600);

  // Prepare relays
  for (int i = 0; i < sizeof(RELEYS); i++) {
    pinMode(RELEYS[i], OUTPUT);
    digitalWrite(RELEYS[i], HIGH);
  }
}

void processData() {
  uint8_t reley_num = RELEYS[received_data[RELEY_NUM] - '0'];
  uint8_t reley_state = received_data[RELEY_STATE] - '0';

  if (reley_state > 1) {
    Serial.println("ERROR: Wrong state");
    resetReceive();
    return;
  }

  Serial.println("Received : ");
  Serial.print(reley_num, HEX);
  Serial.println("");
  Serial.print(reley_state, HEX);
  Serial.println("");
  Serial.println((char *)received_data);

  digitalWrite(reley_num, reley_state);
}

void resetReceive() {
  Serial.println("reset");
  received = 0;
}

void loop() {
  if (Serial.available()) {
    received_byte = Serial.read();

    // Process start
    if (!received) {
      if (BEG_CHAR == received_byte) {
        received = 0;
        received_data[received++] = received_byte;
        Serial.write(received_byte);
      }
      return;
    }
    
    // Process end
    if (END_CHAR == received_byte) {
      Serial.write(received_byte);
      received_data[received++] = received_byte;
      received_data[received++] = 0;
      processData();
      resetReceive();
      return;
    }

    // Body
    if (received < MAX_SZ) {
      if (received_byte >= '0' &&  received_byte <= '3') {
        Serial.write(received_byte);
        received_data[received++] = received_byte;
        return;
      }
    }

    // Wrong symbols
    resetReceive();
  }
}