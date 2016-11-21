package frodo_post_quantum_key_exchange_golang

var (
	LWE_LOG2_Q         = 15  // Log_2 of the modulus Q.
	LWE_EXTRACTED_BITS = 4   // Number of bits extracted from a ring element.
	LWE_N              = 752 // Dimensionality of the lattice.
	LWE_N_BAR          = 8   // Number of vectors chosen by each of the parties.
	LWE_KEY_BITS       = 256 // The length of the reconciled key in bits.
	//LWE_NOISE_D3    // The noise distribution (see lwe_noise.h).
	LWE_PARAMETERS_NAME = "recommended"
	LWE_Q               = (1 << LWE_LOG2_Q)
	LWE_SEED_LENGTH     = 16
	LWE_REC_HINT_LENGTH = LWE_DIV_ROUNDUP(LWE_N_BAR *LWE_N_BAR, 8)
	LWE_PUB_LENGTH =  LWE_DIV_ROUNDUP(LWE_N_BAR *LWE_N *LWE_LOG2_Q, 8)
	LWE_STRIPE_STEP = 8

)


func LWE_DIV_ROUNDUP(x int, y int) (int){
	return (((x) + (y)-1) / y);
}

