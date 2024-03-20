
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import tensorflow as tf

class Encoder(tf.keras.layers.Layer):
    """
            Start of tensorflow autoencoder implementation
    """
    def __init__(self, intermediate_dim, sub_intermediate_dim, training=True):
        super(Encoder, self).__init__()
        self.symb_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.context_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.binary_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.training=training

        self.symb_norm_layer    = tf.keras.layers.BatchNormalization()
        self.context_norm_layer = tf.keras.layers.BatchNormalization()
        self.binary_norm_layer  = tf.keras.layers.BatchNormalization()

        self.symb_embed_drop        = tf.keras.layers.Dropout(0.25)
        self.context_embed_drop     = tf.keras.layers.Dropout(0.25)
        self.binary_embed_drop      = tf.keras.layers.Dropout(0.25)

        self.output_layer = tf.keras.layers.Dense(
                units=intermediate_dim,
                activation=tf.nn.leaky_relu,
                kernel_initializer='random_normal',
                kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))


    def call(self, input_features):
        ndivis          = 3
        n_features      = input_features.shape[2]
        if n_features % ndivis != 0:
            raise RuntimeError("Error, we are expecting n input features to be divisible by {}".format(ndivis))

        symb_feat_len = int(n_features / ndivis)

        #1n
        symb_input_features     = input_features[:,:,:symb_feat_len]
        #2-3n
        context_input_features  = input_features[:,:,symb_feat_len:2*symb_feat_len]
        #4n
        binary_input_features   = input_features[:,:,-symb_feat_len:]

        """
            INPUT -> DENSE SMALL -> BATCH NORM -> DROP -> DENSE OUT
        """


        #activation = self.symb_hidden_layer(input_features)
        #return self.output_layer(activation)
        ## input is sparse and wildly different, apply batch norm after activation
        s_activation    = self.symb_hidden_layer(symb_input_features)
        s_norm          = self.symb_norm_layer(s_activation, training=self.training)
        s_o             = self.symb_embed_drop(s_norm, training=self.training)

        c_activation    = self.context_hidden_layer(context_input_features)
        c_norm          = self.context_norm_layer(c_activation, training=self.training)
        c_o             = self.context_embed_drop(c_norm, training=self.training)

        b_activation    = self.binary_hidden_layer(binary_input_features)
        b_norm          = self.binary_norm_layer(b_activation, training=self.training)
        b_o             = self.binary_embed_drop(b_norm, training=self.training)

        return self.output_layer(tf.keras.layers.concatenate([s_o, c_o, b_o]))

class Decoder(tf.keras.layers.Layer):
    def __init__(self, intermediate_dim, sub_intermediate_dim, original_dim, training=True):
        super(Decoder, self).__init__()
        self.symb_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.context_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.binary_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.training=training

        ##divisable by 4
        assert(original_dim % 3 == 0)
        self.s_output_layer = tf.keras.layers.Dense(
            units=original_dim/3,
            activation=tf.nn.leaky_relu)

        self.c_output_layer = tf.keras.layers.Dense(
            units=original_dim/3,
            activation=tf.nn.leaky_relu)

        self.b_output_layer = tf.keras.layers.Dense(
            units=original_dim/3,
            activation=tf.nn.leaky_relu)

        self.norm_layer        = tf.keras.layers.BatchNormalization()

        self.symb_embed_drop        = tf.keras.layers.Dropout(0.25)
        self.context_embed_drop     = tf.keras.layers.Dropout(0.25)
        self.binary_embed_drop      = tf.keras.layers.Dropout(0.25)

    def call(self, code):
        #print("Decoder::call: {}".format(code.shape))
        #activation = self.hidden_layer(code)
        #return self.output_layer(activation)

        c_norm  = self.norm_layer(code)
        
        s_h         = self.symb_hidden_layer(c_norm)
        s_d         = self.symb_embed_drop(s_h, training=self.training)
        s_o         = self.s_output_layer(s_d, training=self.training)


        c_h         = self.context_hidden_layer(c_norm)
        c_d         = self.context_embed_drop(c_h, training=self.training)
        c_o         = self.c_output_layer(c_d, training=self.training)

        b_h         = self.binary_hidden_layer(c_norm)
        b_d         = self.binary_embed_drop(b_h, training=self.training)
        b_o         = self.b_output_layer(b_d, training=self.training)

        return tf.keras.layers.concatenate([s_o, c_o, b_o])

class Autoencoder(tf.keras.Model):
    def __init__(self, intermediate_dim, sub_intermediate_dim, out_dim, training=False):
        #print("Autoencoder::init")
        super(Autoencoder, self).__init__()
        self.encoder = Encoder(intermediate_dim=intermediate_dim, sub_intermediate_dim=sub_intermediate_dim, training=training)
        self.decoder = Decoder(intermediate_dim=intermediate_dim, sub_intermediate_dim=sub_intermediate_dim, original_dim=out_dim, training=training)        
        self.training = training
		        
        if self.training:
            self.noise = tf.keras.layers.GaussianNoise(0.1)

        
    def call(self, input_features):
        #print("Autoencoder::call: {}".format(input_features.shape))
        #assert(len(input_features.shape) == 3)
        code = self.encoder(input_features)
        
        # Guassian Noise in Training Mode
        if self.training:
            code = self.noise(code)
        
        reconstructed = self.decoder(code)
        return reconstructed
